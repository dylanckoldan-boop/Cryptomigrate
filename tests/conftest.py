"""Shared fixtures. Legacy 3DES *encryption* exists only here (test data), never in the toolkit."""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptomigrate.config import load_config
from cryptomigrate.keys.keystore import Keystore

FIXTURES = Path(__file__).parent / "fixtures"
LEGACY_KEY = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")


def legacy_encrypt(plaintext: bytes, key: bytes = LEGACY_KEY, encoding: str = "base64",
                   mode: str = "CBC") -> bytes | str:
    padder = padding.PKCS7(64).padder()
    data = padder.update(plaintext) + padder.finalize()
    if mode == "CBC":
        iv = os.urandom(8)
        enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
        raw = iv + enc.update(data) + enc.finalize()
    else:
        enc = Cipher(TripleDES(key), modes.ECB()).encryptor()
        raw = enc.update(data) + enc.finalize()
    if encoding == "base64":
        return base64.b64encode(raw).decode()
    if encoding == "hex":
        return raw.hex()
    return raw


@pytest.fixture
def kek(monkeypatch) -> str:
    value = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("CRYPTOMIGRATE_KEK", value)
    monkeypatch.delenv("CRYPTOMIGRATE_KEK_PASSPHRASE", raising=False)
    monkeypatch.setenv("CRYPTOMIGRATE_ACTOR", "pytest")
    return value


PEOPLE = [(1, "Ada", b"123-45-6789", b"4111111111111111"), (2, "Grace", b"987-65-4321", b"5500000000000004"),
          (3, "Alan", b"111-22-3333", b"340000000000009"), (4, "Edsger", b"", b"6011000000000004"),
          (5, "Barbara", b"555-44-3333", None), (6, "Ken", b"222-33-4444", b"3530111333300000"),
          (7, "Dennis", b"333-44-5555", b"4000056655665556")]
FILES = {"2019/contract-001.enc": b"Master services agreement v1", "2020/contract-002.enc": b"Amendment #2 " * 50,
         "readme.enc": b"x"}


def build_legacy_project(root: Path, extra: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / "legacy.db")
    db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, ssn_enc TEXT, card_enc BLOB)")
    for pk, name, ssn, card in PEOPLE:
        db.execute("INSERT INTO customers VALUES (?, ?, ?, ?)", (
            pk, name, legacy_encrypt(ssn) if ssn else "",
            legacy_encrypt(card, encoding="raw") if card is not None else None))
    db.commit()
    db.close()
    for rel, content in FILES.items():
        path = root / "archive" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(legacy_encrypt(content, encoding="raw"))
    config = {
        "project": {"name": "Test migration", "organization": "Test Org", "sponsor": "S. Ponsor",
                    "project_manager": "P. Manager", "security_lead": "S. Lead", "target_completion": "2027-06-30",
                    "compliance_frameworks": ["NIST-SP-800-131A"]},
        "systems": [{"id": "portal", "name": "Customer Portal", "owner": "A. Owner", "criticality": "high",
                     "paths": ["src/**"]},
                    {"id": "records", "name": "Records Archive", "owner": "R. Owner", "criticality": "low"}],
        "legacy_profiles": {
            "tdes-b64": {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7",
                         "encoding": "base64", "key_id": "legacy-3des"},
            "tdes-raw": {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7", "encoding": "raw",
                         "key_id": "legacy-3des"}},
        "data_sources": [
            {"name": "customers", "system": "portal", "adapter": "sql", "driver": "sqlite3",
             "connect": {"database": "legacy.db"}, "table": "customers", "primary_key": "id", "batch_size": 3,
             "columns": [{"name": "ssn_enc", "legacy_profile": "tdes-b64", "storage": "text"},
                         {"name": "card_enc", "legacy_profile": "tdes-raw", "storage": "blob"}]},
            {"name": "archive", "system": "records", "adapter": "files", "path": "archive", "glob": "**/*.enc",
             "legacy_profile": "tdes-raw", "batch_size": 2}],
        "governance": {"require_change_ticket": False},
        "scan": {"paths": ["src"]},
    }
    for key, value in (extra or {}).items():
        config[key] = value
    (root / "src").mkdir(exist_ok=True)
    (root / "migration.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
    return root / "migration.yaml"


@pytest.fixture
def project(tmp_path, kek):
    """A legacy system (SQLite + encrypted files) with a keystore holding an AES key and the legacy key."""
    cfg = load_config(build_legacy_project(tmp_path / "proj"))
    store = Keystore.from_config(cfg, create=True)
    store.generate(256)
    store.import_legacy("legacy-3des", "3DES", LEGACY_KEY)
    return cfg, store
