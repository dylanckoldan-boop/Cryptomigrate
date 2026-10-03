#!/usr/bin/env python3
"""Build a realistic *legacy* system for the end-to-end demo, and simulate the human steps.

cryptomigrate: ignore-file -- demo generator: deliberately creates legacy crypto and insecure sample code as test data

    make_legacy_system.py WS create                 legacy app, configs, SQLite DB, encrypted archive, migration.yaml
    make_legacy_system.py WS modernize              Phase 4: the developers' AES-GCM code changes (simulated PRs)
    make_legacy_system.py WS signoff GATE "Who"     record a manual gate approval in migration.yaml
    make_legacy_system.py WS set KEY.PATH VALUE     edit migration.yaml (e.g. migration.mode strict)
    make_legacy_system.py WS asset NAME STATUS      update a manual asset (e.g. HSM remediated)
    make_legacy_system.py WS approve GATE "Who"     add an approval (e.g. dual control for key destruction)

All people, SSNs and card numbers are fake. The legacy 3DES key is random per run and written to
legacy-key.hex - standing in for the key custodian's hand-over during the key ceremony.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
import random
import sqlite3
import sys
import textwrap
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def tdes_cbc(key: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(64).padder()
    iv = os.urandom(8)
    enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def tdes_cbc_raw(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(64).padder()
    enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def legacy_pem(private_key, passphrase: bytes) -> bytes:
    """Traditional OpenSSL PEM encrypted with DES-EDE3-CBC (what `openssl genrsa -des3` produced for years)."""
    der = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
    iv, derived, block = os.urandom(8), b"", b""
    while len(derived) < 24:  # EVP_BytesToKey(MD5, salt = IV)
        block = hashlib.md5(block + passphrase + iv).digest()
        derived += block
    body = "\n".join(textwrap.wrap(base64.b64encode(tdes_cbc_raw(derived[:24], iv, der)).decode(), 64))
    return (f"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,{iv.hex().upper()}\n\n"
            f"{body}\n-----END RSA PRIVATE KEY-----\n").encode()


def make_cert(cn: str, key, issuer_name=None, issuer_key=None, start=None, days=90, san=True, ca=False):
    start = start or datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start)
               .not_valid_after(start + datetime.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


LEGACY_SOURCES = {
    "legacy_app/payments/PaymentCrypto.java": '''package com.example.payments;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Encrypts card numbers before they are stored (written 2009). */
public class PaymentCrypto {
    public byte[] protectPan(byte[] key, byte[] iv, byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        return cipher.doFinal(pan);
    }
}
''',
    "legacy_app/payments/application.properties": "payments.crypto.algorithm=DESede/CBC/PKCS5Padding\n"
                                                  "payments.crypto.key-alias=pan-key\n",
    "legacy_app/portal/ssn_vault.py": '''"""SSN vault for the customer portal (legacy)."""
import base64
import os

import requests
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad


def protect_ssn(key: bytes, ssn: str) -> str:
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(ssn.encode(), 8))).decode()


def lookup(conn, customer_id):
    return conn.execute(f"SELECT ssn_enc FROM customers WHERE id = {customer_id}").fetchone()


def sync_to_crm(record):
    return requests.post("https://crm.example.internal/api/customers", json=record, verify=False)
''',
    "legacy_app/messaging/envelope.py": '''"""Secure-messaging envelope (legacy, 2011): an RSA-wrapped Triple-DES content key per message."""
import os

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding as sym
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes


def seal(recipient_public_key, body: bytes) -> bytes:
    content_key, iv = os.urandom(24), os.urandom(8)
    padder = sym.PKCS7(64).padder()
    enc = Cipher(TripleDES(content_key), modes.CBC(iv)).encryptor()
    wrapped = recipient_public_key.encrypt(content_key, padding.PKCS1v15())
    return wrapped + iv + enc.update(padder.update(body) + padder.finalize()) + enc.finalize()
''',
    "legacy_app/payments/hsm_bridge.c": '''/* Bridge to the payment HSM (legacy). */
#include <stdio.h>
#include <string.h>

int format_command(char *out, const char *pan) {
    char buf[64];
    strcpy(buf, pan);
    sprintf(out, "M0%s", buf);
    return 0;
}
''',
    "legacy_app/payments/Makefile": "CFLAGS += -O2 -fno-stack-protector\n",
    "infra/wifi/hostapd.conf": ("interface=wlan0\nssid=ExampleCorp-Guest\nwpa=2\nwpa_key_mgmt=WPA-PSK\n"
                                "wpa_pairwise=TKIP\nrsn_pairwise=CCMP TKIP\nieee80211w=0\nwps_state=2\n"),
    "legacy_app/archive-svc/archive.go": '''package archive

import (
	"crypto/cipher"
	"crypto/des"
)

// Seal encrypts a contract before it is written to the archive share.
func Seal(key, iv, data []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return append(iv, out...), nil
}
''',
    "infra/nginx/nginx.conf": '''server {
    listen 443 ssl;
    server_name portal.example.internal;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA';
}
''',
    "infra/ssh/sshd_config": "Port 22\nPermitRootLogin no\nCiphers aes256-gcm@openssh.com,aes128-ctr,3des-cbc\n",
}

MODERN_SOURCES = {
    "legacy_app/payments/PaymentCrypto.java": '''package com.example.payments;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Encrypts card numbers with AES-256-GCM (migrated from Triple-DES, WBS 4.1). */
public class PaymentCrypto {
    public byte[] protectPan(byte[] key, byte[] nonce, byte[] pan, byte[] context) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(context);
        return cipher.doFinal(pan);
    }
}
''',
    "legacy_app/payments/application.properties": "payments.crypto.algorithm=AES-256-GCM\n"
                                                  "payments.crypto.key-alias=pan-key\n",
    "legacy_app/portal/ssn_vault.py": '''"""SSN vault for the customer portal (AES-256-GCM, WBS 4.1)."""
from cryptomigrate import CryptoService

_service = CryptoService.from_config("migration.yaml")


def protect_ssn(customer_id: int, ssn: str) -> str:
    return _service.encrypt_text(ssn.encode(), context=f"customers.ssn_enc#{customer_id}")


def reveal_ssn(customer_id: int, stored: str) -> str:
    return _service.decrypt(stored, context=f"customers.ssn_enc#{customer_id}", legacy_profile="tdes-base64").decode()


def lookup(conn, customer_id: int):
    return conn.execute("SELECT ssn_enc FROM customers WHERE id = ?", (customer_id,)).fetchone()
''',
    "legacy_app/messaging/envelope.py": '''"""Secure-messaging envelope: AES-256-GCM content key, RSA-OAEP-SHA256 key transport (WBS 4.1)."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def seal(recipient_public_key, body: bytes, context: bytes) -> bytes:
    content_key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    wrapped = recipient_public_key.encrypt(content_key, OAEP)
    return wrapped + nonce + AESGCM(content_key).encrypt(nonce, body, context)
''',
    "legacy_app/payments/hsm_bridge.c": '''/* Bridge to the payment HSM: bounded string handling (WBS 4.1). */
#include <stdio.h>
#include <string.h>

int format_command(char *out, size_t out_len, const char *pan) {
    char buf[64];
    if (snprintf(buf, sizeof buf, "%s", pan) >= (int)sizeof buf) return -1;
    return snprintf(out, out_len, "M0%s", buf) < (int)out_len ? 0 : -1;
}
''',
    "legacy_app/payments/Makefile": ("CFLAGS += -O2 -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fPIE\n"
                                     "LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack\n"),
    "infra/wifi/hostapd.conf": ("interface=wlan0\nssid=ExampleCorp-Guest\nwpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\n"
                                "ieee80211w=2\nsae_require_mfp=1\nwps_state=0\n"),
    "legacy_app/archive-svc/archive.go": '''package archive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Seal encrypts a contract with AES-256-GCM before it is written to the archive share.
func Seal(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}
''',
}

FIRST = ["Ada", "Grace", "Alan", "Edsger", "Barbara", "Ken", "Dennis", "Margaret", "Linus", "Frances"]
LAST = ["Lovelace", "Hopper", "Turing", "Dijkstra", "Liskov", "Thompson", "Ritchie", "Hamilton", "Torvalds", "Allen"]


def create(ws: Path) -> None:
    rng = random.Random(2026)  # deterministic fake data
    key = os.urandom(24)
    (ws / "legacy-key.hex").write_text(key.hex() + "\n")
    for rel, text in LEGACY_SOURCES.items():
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    db = sqlite3.connect(ws / "legacy.db")
    db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn_enc VARCHAR(128))")
    db.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, customer_id INTEGER, amount_cents INTEGER, "
               "pan_enc BLOB)")
    for i in range(1, 51):
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        ssn = f"9{rng.randint(10, 99)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"  # 9xx = never issued
        db.execute("INSERT INTO customers VALUES (?, ?, ?, ?)",
                   (i, name, f"user{i}@example.com", base64.b64encode(tdes_cbc(key, ssn.encode())).decode()))
    for i in range(1, 121):
        pan = rng.choice(["4111111111111111", "5500000000000004", "340000000000009", "6011000000000004"])
        db.execute("INSERT INTO payments VALUES (?, ?, ?, ?)",
                   (i, rng.randint(1, 50), rng.randint(500, 250000), tdes_cbc(key, pan.encode())))
    db.commit()
    db.close()
    legacy_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # the messaging system's key
    (ws / "legacy-rsa.pem").write_bytes(legacy_rsa.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    db = sqlite3.connect(ws / "legacy.db")
    db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, body_enc BLOB)")
    for i in range(1, 41):  # hybrid records: RSA-PKCS#1 v1.5(3DES key) || IV || 3DES-CBC(body)
        content_key, iv = os.urandom(24), os.urandom(8)
        body = f"Message {i}: statement for {rng.choice(FIRST)} is ready.".encode()
        record = legacy_rsa.public_key().encrypt(content_key, rsa_padding.PKCS1v15()) + iv + tdes_cbc_raw(content_key, iv, body)
        db.execute("INSERT INTO messages VALUES (?, ?, ?)", (i, f"system{i % 3}@example.com", record))
    db.commit()
    db.close()
    certs = ws / "infra" / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    expired = make_cert("portal.example.internal", weak_key, san=False, days=365,
                        start=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=500))
    (certs / "portal-legacy.pem").write_bytes(expired.public_bytes(serialization.Encoding.PEM))
    (certs / "portal-legacy.key").write_bytes(legacy_pem(weak_key, b"changeit"))
    for i in range(1, 13):
        path = ws / "archive" / f"{2014 + i // 4}" / f"contract-{i:03d}.pdf.enc"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(tdes_cbc(key, f"%PDF-1.4 fake contract {i} ".encode() * rng.randint(5, 60)))
    config = {
        "project": {"name": "Legacy cryptography retirement (demo)", "organization": "Example Corp",
                    "sponsor": "Jordan Rivera (CIO)", "project_manager": "Casey Kim (PMO)",
                    "security_lead": "Avery Patel (CISO)",
                    "target_completion": (datetime.date.today() + datetime.timedelta(days=180)).isoformat(),
                    "compliance_frameworks": ["NIST-SP-800-131A", "PCI-DSS-4.0", "ISO-27001"]},
        "policy": "des-to-aes",
        "layers": ["pki-tls", "auth-wireless", "secure-coding"],
        "scan": {"paths": ["legacy_app", "infra"]},
        "systems": [
            {"id": "records-archive", "name": "Records Archive", "owner": "Dana Ortiz (Records Manager)",
             "criticality": "low", "paths": ["legacy_app/archive-svc/**"]},
            {"id": "edge", "name": "Edge & Access", "owner": "Sam Okafor (Platform)", "criticality": "medium",
             "paths": ["infra/**"]},
            {"id": "customer-portal", "name": "Customer Portal", "owner": "Priya Shah (Portal Lead)",
             "criticality": "high", "data_classification": "restricted", "paths": ["legacy_app/portal/**"]},
            {"id": "payments", "name": "Payments", "owner": "Marcus Lee (Payments Lead)", "criticality": "critical",
             "data_classification": "PCI cardholder data", "paths": ["legacy_app/payments/**"]},
            {"id": "secure-messaging", "name": "Secure Messaging", "owner": "Lena Novak (Messaging Lead)",
             "criticality": "medium", "data_classification": "confidential", "paths": ["legacy_app/messaging/**"]},
        ],
        "manual_assets": [{"name": "Payment HSM cluster", "type": "hsm", "system": "payments", "algorithm": "3DES",
                           "mode": "CBC", "aes_support": "firmware-update", "owner": "Marcus Lee",
                           "status": "open", "notes": "PIN/PAN keys; vendor AES firmware scheduled"}],
        "target": {"algorithm": "AES-256-GCM"},
        "legacy_profiles": {
            "tdes-base64": {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7",
                            "encoding": "base64", "key_id": "legacy-3des"},
            "tdes-raw": {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7", "encoding": "raw",
                         "key_id": "legacy-3des"},
            "hybrid-rsa-3des": {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7", "encoding": "raw",
                                "key_transport": "rsa-pkcs1v15", "rsa_key_bits": 2048, "key_id": "legacy-rsa"}},
        "data_sources": [
            {"name": "contract-archive", "system": "records-archive", "adapter": "files", "path": "archive",
             "glob": "**/*.enc", "legacy_profile": "tdes-raw", "batch_size": 5},
            {"name": "customers-ssn", "system": "customer-portal", "adapter": "sql", "driver": "sqlite3",
             "connect": {"database": "legacy.db"}, "table": "customers", "primary_key": "id",
             "columns": [{"name": "ssn_enc", "legacy_profile": "tdes-base64", "storage": "text",
                          "max_length": 128}], "batch_size": 20},
            {"name": "payments-pan", "system": "payments", "adapter": "sql", "driver": "sqlite3",
             "connect": {"database": "legacy.db"}, "table": "payments", "primary_key": "id",
             "columns": [{"name": "pan_enc", "legacy_profile": "tdes-raw", "storage": "blob"}], "batch_size": 50},
            {"name": "secure-messages", "system": "secure-messaging", "adapter": "sql", "driver": "sqlite3",
             "connect": {"database": "legacy.db"}, "table": "messages", "primary_key": "id",
             "columns": [{"name": "body_enc", "legacy_profile": "hybrid-rsa-3des", "storage": "blob"}], "batch_size": 20},
        ],
        "migration": {"mode": "dual", "backup": True},
        "nfr": {"max_latency_increase_pct": 10, "benchmark_record_bytes": 256},
        "governance": {"require_change_ticket": True, "dual_control": True, "approvals": {},
                       "signoffs": {"charter": {"by": "Jordan Rivera (CIO)", "date": datetime.date.today().isoformat(),
                                                "ref": "demo: charter issue #1"}},
                       "exceptions": []},
    }
    (ws / "migration.yaml").write_text("# Generated by examples/demo/make_legacy_system.py\n" +
                                       yaml.safe_dump(config, sort_keys=False))
    print(f"Legacy system created in {ws}: 50 customers, 120 payments, 40 hybrid RSA+3DES messages, 12 archived "
          "contracts, legacy code/configs/Wi-Fi/certificates, 1 HSM (manual inventory).")


def _edit(ws: Path, fn) -> None:
    path = ws / "migration.yaml"
    data = yaml.safe_load(path.read_text())
    fn(data)
    path.write_text("# Generated by examples/demo/make_legacy_system.py\n" + yaml.safe_dump(data, sort_keys=False))


def main(argv: list[str]) -> int:
    ws, action, *rest = Path(argv[0]).resolve(), argv[1], *argv[2:]
    if action == "create":
        ws.mkdir(parents=True, exist_ok=True)
        create(ws)
    elif action == "modernize":
        for rel, text in MODERN_SOURCES.items():
            (ws / rel).write_text(text)
        certs = ws / "infra" / "certs"  # PKI team re-issues: CA-signed ECDSA P-256, SAN, 90 days; key moved to HSM
        for old in ("portal-legacy.pem", "portal-legacy.key"):
            (certs / old).unlink(missing_ok=True)
        ca_key, leaf_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP256R1())
        ca = make_cert("Example Corp Issuing CA", ca_key, ca=True, days=1825)
        leaf = make_cert("portal.example.internal", leaf_key, ca.subject, ca_key, days=90)
        (certs / "portal.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                           ca.public_bytes(serialization.Encoding.PEM))
        print(f"Applied {len(MODERN_SOURCES)} developer changes (simulated pull requests) - AES-256-GCM everywhere.")
    elif action == "signoff":
        gate, who = rest
        _edit(ws, lambda d: d["governance"]["signoffs"].update(
            {gate: {"by": who, "date": datetime.date.today().isoformat(), "ref": f"demo: {gate} approval"}}))
        print(f"Recorded sign-off '{gate}' by {who}")
    elif action == "set":
        dotted, value = rest

        def setter(d):
            node = d
            *parents, leaf = dotted.split(".")
            for part in parents:
                node = node.setdefault(part, {})
            node[leaf] = value
        _edit(ws, setter)
    elif action == "approve":
        gate, who = rest
        _edit(ws, lambda d: d["governance"].setdefault("approvals", {}).setdefault(gate, []).append(
            {"by": who, "date": datetime.date.today().isoformat(), "ref": f"demo: {gate} approval"}))
        print(f"Recorded approval for '{gate}' by {who}")
    elif action == "asset":
        name, status = rest
        _edit(ws, lambda d: [a.update(status=status) for a in d["manual_assets"] if a["name"] == name])
        print(f"Manual asset '{name}' -> {status}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
