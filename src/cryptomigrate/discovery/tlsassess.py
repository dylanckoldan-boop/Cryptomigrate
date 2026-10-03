"""Transport layer & SSL/TLS handshake assessment of live endpoints.

cryptomigrate: ignore-file=TLS-VERIFY-001 -- the assessor must handshake with untrusted certs to report them

For each endpoint: which legacy protocol versions (SSLv3, TLS 1.0, TLS 1.1) the server still negotiates (raw
ClientHello probes, independent of the local OpenSSL), whether a TLS 1.2+ handshake succeeds with full
certificate-chain and hostname verification, whether the negotiated key exchange gives forward secrecy, and the
server certificate itself (analysed by the certificate layer). Only assess endpoints you are authorised to test.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

from .tlsprobe import parse_endpoint, protocol_accepted

LEGACY_PROTOCOLS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1"}


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> tuple[str, str, bytes]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version() or "", tls.cipher()[0], tls.getpeercert(binary_form=True)


def assess_endpoint(endpoint: str, ca_bundle: str | None = None, timeout: float = 5.0) -> dict[str, Any]:
    result: dict[str, Any] = {"endpoint": endpoint, "reachable": True, "legacy_protocols": [],
                              "unknown_protocols": [], "protocol": None, "cipher": None, "forward_secrecy": None,
                              "verified": None, "verify_error": None, "modern_error": None, "certificate_der": None}
    try:
        host, port = parse_endpoint(endpoint)
    except ValueError:
        result.update(reachable=False, modern_error="cannot parse endpoint (use host:port)")
        return result
    for version, name in LEGACY_PROTOCOLS.items():
        accepted, _ = protocol_accepted(endpoint, version, timeout)
        if accepted:
            result["legacy_protocols"].append(name)
        elif accepted is None:
            result["unknown_protocols"].append(name)
    der = None
    verifying = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    try:
        result["protocol"], result["cipher"], der = _handshake(host, port, verifying, timeout)
        result["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        result.update(verified=False, verify_error=exc.verify_message or str(exc))
    except ssl.SSLError as exc:
        result["modern_error"] = str(exc)
    except OSError as exc:
        result.update(reachable=False, modern_error=str(exc))
    if der is None and result["reachable"]:
        inspect = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        inspect.check_hostname = False
        inspect.verify_mode = ssl.CERT_NONE
        try:
            protocol, cipher, der = _handshake(host, port, inspect, timeout)
            result["protocol"], result["cipher"] = result["protocol"] or protocol, result["cipher"] or cipher
        except (ssl.SSLError, OSError) as exc:
            result["modern_error"] = result["modern_error"] or str(exc)
    if result["protocol"]:
        result["forward_secrecy"] = (result["protocol"] == "TLSv1.3"
                                     or str(result["cipher"]).startswith(("ECDHE", "DHE")))
    result["certificate_der"] = der
    return result
