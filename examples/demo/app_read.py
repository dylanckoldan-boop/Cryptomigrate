#!/usr/bin/env python3
"""Simulates the application's read path through CryptoService (masked output - never print full SSNs/PANs).

Before migration it reads legacy 3DES (dual mode); after migration it reads AES-GCM; in strict mode any value
that is still legacy fails closed.
"""

import sqlite3
import sys

from cryptomigrate import CryptoService

svc = CryptoService.from_config("migration.yaml")
db = sqlite3.connect("legacy.db")
checks = [
    ("customer 1 SSN", db.execute("SELECT ssn_enc FROM customers WHERE id = 1").fetchone()[0],
     "customers.ssn_enc#1", "tdes-base64"),
    ("payment 1 PAN ", db.execute("SELECT pan_enc FROM payments WHERE id = 1").fetchone()[0],
     "payments.pan_enc#1", "tdes-raw"),
    ("message 1     ", db.execute("SELECT body_enc FROM messages WHERE id = 1").fetchone()[0],
     "messages.body_enc#1", "hybrid-rsa-3des"),
]
status = 0
for label, stored, context, profile in checks:
    result = svc.classify(stored, context, profile)
    if result.kind in ("v2", "legacy"):
        text = result.plaintext.decode()
        algorithm = "AES-256-GCM" if result.kind == "v2" else ("legacy RSA+3DES hybrid" if "hybrid" in profile
                                                                else "legacy 3DES")
        print(f"  app read {label}: {'*' * min(12, len(text) - 4)}{text[-4:]}  (stored as {algorithm}, mode={svc.mode})")
    else:
        print(f"  app read {label}: FAILED - {result.error}")
        status = 1
sys.exit(status)
