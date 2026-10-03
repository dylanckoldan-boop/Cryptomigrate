"""Certificate layer: X.509 inventory and hygiene checks for certificate files and live TLS endpoints.

Checks: weak signature hash (MD5/SHA-1), weak public key (RSA < 2048 bits, DSA, EC < 224 bits), expired or soon to
expire, self-signed end-entity, missing subjectAltName, and a validity period longer than the CA/Browser Forum
Baseline Requirements allowed when the certificate was issued (publicly-trusted TLS certificates; ballots SC-31 and
SC-081v3). Trust anchors - self-signed CA certificates, e.g. in CA bundles - are exempt from signature and expiry
checks because their signatures are never verified.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .scanner import Finding, fingerprint

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".cert"}
MAX_CERT_FILE = 2 * 1024 * 1024
CABF_SCHEDULE = [(dt.date(2029, 3, 15), 47), (dt.date(2027, 3, 15), 100), (dt.date(2026, 3, 15), 200),
                 (dt.date(2020, 9, 1), 398)]


def cabf_max_validity(issued: dt.date) -> int | None:
    """Maximum validity (days) for a publicly-trusted TLS certificate issued on ``issued``."""
    for start, days in CABF_SCHEDULE:
        if issued >= start:
            return days
    return None


def load_certificates(data: bytes) -> list[x509.Certificate]:
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificates(data)
        if data[:1] == b"\x30":
            return [x509.load_der_x509_certificate(data)]
    except ValueError:
        pass
    return []


def _utc(cert: x509.Certificate, name: str) -> dt.datetime:
    value = getattr(cert, f"{name}_utc", None)
    return value if value is not None else getattr(cert, name).replace(tzinfo=dt.timezone.utc)


def describe(cert: x509.Certificate) -> dict[str, Any]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = f"EC-{key.curve.name}", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 456
    else:
        key_type, bits = type(key).__name__, None
    is_ca, sans, tls_server = False, [], True
    try:
        ext = cert.extensions
        try:
            is_ca = bool(ext.get_extension_for_class(x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            pass
        try:
            san = ext.get_extension_for_class(x509.SubjectAlternativeName).value
            sans = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            pass
        try:
            tls_server = ExtendedKeyUsageOID.SERVER_AUTH in ext.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            tls_server = not is_ca
    except ValueError:  # malformed or duplicate extensions
        pass
    try:
        sig = cert.signature_hash_algorithm
        signature_hash = sig.name if sig else None
    except Exception:  # noqa: BLE001 - unsupported signature algorithms
        signature_hash = "unknown"
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "common_name": str(cn[0].value) if cn else None, "serial": format(cert.serial_number, "x"),
            "not_before": _utc(cert, "not_valid_before").isoformat(),
            "not_after": _utc(cert, "not_valid_after").isoformat(),
            "signature_hash": signature_hash, "signature_oid": cert.signature_algorithm_oid.dotted_string,
            "key_type": key_type, "key_bits": bits, "is_ca": is_ca, "self_signed": cert.issuer == cert.subject,
            "sans": sans, "tls_server": tls_server and not is_ca, "sha256": cert.fingerprint(hashes.SHA256()).hex()}


def analyze_certificate(cert: x509.Certificate, policy, location: str, origin: str, warn_days: int = 30,
                        now: dt.datetime | None = None) -> tuple[list[Finding], dict[str, Any]]:
    info = {**describe(cert), "location": location, "origin": origin}
    now = now or dt.datetime.now(dt.timezone.utc)
    label = info["common_name"] or info["subject"] or "certificate"
    found: list[Finding] = []

    def add(rule_id: str, algorithm: str, detail: str) -> None:
        rule = policy.rule(rule_id)
        found.append(Finding(
            rule_id=rule.id, title=rule.title, category="certificate", algorithm=algorithm,
            severity=rule.severity_for(algorithm), confidence=rule.confidence, location=location,
            detail=f"{label}: {detail}", fingerprint=fingerprint(rule.id, location, info["sha256"]),
            cwe=list(rule.cwe), remediation=rule.remediation, layer=rule.pack,
            evidence={"origin": origin, "sha256": info["sha256"], "subject": info["subject"]}))

    anchor = info["is_ca"] and info["self_signed"]
    sig = (info["signature_hash"] or "").lower()
    if sig in ("md5", "sha1") and not anchor:
        add("CERT-SIG-001", "MD5" if sig == "md5" else "SHA-1", f"signed with {sig.upper()}")
    key_type, bits = info["key_type"], info["key_bits"] or 0
    if (key_type == "RSA" and bits < 2048) or key_type == "DSA" or (key_type.startswith("EC-") and bits < 224):
        add("CERT-KEY-001", "EC" if key_type.startswith("EC-") else key_type, f"{key_type} {bits}-bit public key")
    not_before = dt.datetime.fromisoformat(info["not_before"])
    not_after = dt.datetime.fromisoformat(info["not_after"])
    if not anchor:
        if not_after < now:
            add("CERT-EXP-001", "n/a", f"expired on {not_after.date()}")
        elif (not_after - now).days <= warn_days:
            add("CERT-EXP-002", "n/a", f"expires on {not_after.date()} ({(not_after - now).days} days)")
    if not info["is_ca"]:
        if info["self_signed"]:
            add("CERT-SELF-001", "n/a", "self-signed end-entity certificate")
        if info["tls_server"]:
            if not info["sans"]:
                add("CERT-SAN-001", "n/a", "no subjectAltName (CN-only names are rejected by modern clients)")
            limit = cabf_max_validity(not_before.date())
            days = (not_after - not_before).days
            if limit and days > limit:
                add("CERT-LIFE-001", "n/a", f"{days}-day validity exceeds the {limit}-day CA/Browser Forum maximum "
                                            "in force when it was issued (publicly-trusted certificates)")
    return found, info


def scan_certificate_files(cfg, policy, scanner, roots: list[Path]) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    records: list[dict[str, Any]] = []
    ignored = scanner.stats["files_ignored"]
    for path, rel in scanner.walk(roots):
        if path.suffix.lower() not in CERT_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_CERT_FILE:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        for cert in load_certificates(data):
            found, info = analyze_certificate(cert, policy, rel, "file", cfg.cert_warn_days)
            findings += found
            records.append(info)
    scanner.stats["files_ignored"] = ignored
    return findings, records
