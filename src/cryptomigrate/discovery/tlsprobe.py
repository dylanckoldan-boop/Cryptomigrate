"""Wire-level TLS probes: does an endpoint still accept DES/3DES suites or legacy protocol versions?

cryptomigrate: ignore-file=CM-TLS-002 -- the probe offers DES suites in order to *detect* servers that accept them

The probe writes its own ClientHello and reads the ServerHello. It never completes a handshake and needs no
local cipher support. That matters: modern OpenSSL builds (e.g. Ubuntu 24.04) cannot offer 3DES or TLS 1.0 at
all, so library-based checks silently report "not accepted" even against a vulnerable server.

Statuses: ``accepted`` (finding), ``not-accepted``, ``unreachable``, ``inconclusive``.
Only probe endpoints you own or are authorised to assess.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import asdict, dataclass

# IANA TLS cipher suite registry - every suite in this table is DES-based.
DES_SUITES: dict[int, str] = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008F: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0093: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
    0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
    0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
}
# TLS 1.0/1.1-era suites (AES-CBC, 3DES, RC4) used to test whether a server still accepts a legacy *version*.
LEGACY_ERA_SUITES = [0xC013, 0xC014, 0xC009, 0xC00A, 0x002F, 0x0035, 0x0033, 0x0039, 0x000A, 0x0005, 0x0004]
RENEGOTIATION_SCSV = 0x00FF
VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2"}
ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 112: "unrecognized_name"}
_REJECTION_ALERTS = {40, 70, 71, 86}


@dataclass
class ProbeResult:
    endpoint: str
    status: str  # accepted | not-accepted | unreachable | inconclusive
    cipher: str | None = None
    protocol: str | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Hello:
    status: str  # server-hello | alert | closed | unreachable | timeout | error
    version: int | None = None
    suite: int | None = None
    alert: int | None = None
    detail: str = ""


def parse_endpoint(endpoint: str, default_port: int = 443) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint.startswith("["):  # [IPv6]:port
        host, _, rest = endpoint[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    if endpoint.count(":") == 1:
        host, port = endpoint.split(":")
        return host, int(port)
    return endpoint, default_port


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _u16_list(values: list[int]) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in values)
    return struct.pack("!H", len(body)) + body


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_client_hello(host: str, version: int = 0x0303, suites: list[int] | None = None) -> bytes:
    offered = list(DES_SUITES if suites is None else suites) + [RENEGOTIATION_SCSV]
    body = version.to_bytes(2, "big") + os.urandom(32) + b"\x00"  # client_version, random, empty session id
    body += _u16_list(offered) + b"\x01\x00"  # suites; compression: null only
    if version >= 0x0301:  # SSLv3 hellos are sent without extensions
        extensions = b""
        if host and not _is_ip(host):
            name = host.encode("idna")
            server_name = b"\x00" + struct.pack("!H", len(name)) + name
            extensions += _ext(0x0000, struct.pack("!H", len(server_name)) + server_name)
        extensions += _ext(0x000A, _u16_list([0x001D, 0x0017, 0x0018]))  # supported_groups
        extensions += _ext(0x000B, b"\x01\x00")  # ec_point_formats: uncompressed
        extensions += _ext(0x000D, _u16_list([0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0804, 0x0805, 0x0201, 0x0203]))
        body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record_version = b"\x03\x00" if version == 0x0300 else b"\x03\x01"
    return b"\x16" + record_version + struct.pack("!H", len(handshake)) + handshake


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError("connection closed by peer")
        data += chunk
    return data


def hello(endpoint: str, version: int = 0x0303, suites: list[int] | None = None, timeout: float = 5.0) -> Hello:
    """Send one ClientHello and report the server's first answer."""
    try:
        host, port = parse_endpoint(endpoint)
    except ValueError:
        return Hello("error", detail="cannot parse endpoint (use host:port)")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return Hello("unreachable", detail=str(exc))
    with sock:
        sock.settimeout(timeout)
        try:
            sock.sendall(build_client_hello(host, version, suites))
            buffer = b""
            while True:
                header = _recv_exact(sock, 5)
                content_type, length = header[0], int.from_bytes(header[3:5], "big")
                if length > 18432:
                    return Hello("error", detail="oversized TLS record (not a TLS server?)")
                payload = _recv_exact(sock, length)
                if content_type == 21:
                    code = payload[1] if len(payload) > 1 else -1
                    return Hello("alert", alert=code, detail=ALERTS.get(code, f"alert {code}"))
                if content_type != 22:
                    return Hello("error", detail=f"unexpected TLS record type {content_type}")
                buffer += payload
                if len(buffer) < 4:
                    continue
                if buffer[0] != 2:
                    return Hello("error", detail=f"unexpected handshake type {buffer[0]}")
                hs_len = int.from_bytes(buffer[1:4], "big")
                if len(buffer) < 4 + hs_len:
                    continue
                body = buffer[4:4 + hs_len]
                sid_len = body[34]
                return Hello("server-hello", int.from_bytes(body[0:2], "big"),
                             int.from_bytes(body[35 + sid_len:37 + sid_len], "big"))
        except (ConnectionResetError, BrokenPipeError):
            return Hello("closed", detail="server closed the connection without negotiating")
        except TimeoutError:
            return Hello("timeout", detail=f"no response within {timeout}s")
        except (OSError, IndexError) as exc:
            return Hello("error", detail=f"{type(exc).__name__}: {exc}")


def probe(endpoint: str, timeout: float = 5.0) -> ProbeResult:
    """Does the endpoint negotiate a DES/3DES suite?"""
    h = hello(endpoint, 0x0303, list(DES_SUITES), timeout)
    if h.status == "server-hello":
        if h.suite in DES_SUITES:
            return ProbeResult(endpoint, "accepted", DES_SUITES[h.suite], VERSIONS.get(h.version, hex(h.version or 0)),
                               "server selected a DES-family suite (Sweet32 exposure, CVE-2016-2183)")
        return ProbeResult(endpoint, "inconclusive", detail=f"server chose un-offered suite 0x{h.suite:04X}")
    if h.status == "alert":
        if h.alert in _REJECTION_ALERTS or h.alert == -1:
            return ProbeResult(endpoint, "not-accepted", detail=f"server refused all DES suites ({h.detail})")
        return ProbeResult(endpoint, "inconclusive", detail=f"server sent {h.detail}")
    if h.status == "closed":
        return ProbeResult(endpoint, "not-accepted", detail=h.detail)
    if h.status == "unreachable":
        return ProbeResult(endpoint, "unreachable", detail=h.detail)
    return ProbeResult(endpoint, "inconclusive", detail=h.detail)


def protocol_accepted(endpoint: str, version: int, timeout: float = 5.0) -> tuple[bool | None, str]:
    """True if the server negotiates exactly ``version``; None when the answer is unknown."""
    h = hello(endpoint, version, LEGACY_ERA_SUITES, timeout)
    if h.status == "server-hello":
        return h.version == version, f"server answered with {VERSIONS.get(h.version, hex(h.version or 0))}"
    if h.status in ("alert", "closed"):
        return False, h.detail
    return None, h.detail


def probe_all(endpoints: list[str], timeout: float = 5.0) -> list[ProbeResult]:
    return [probe(e, timeout) for e in dict.fromkeys(endpoints)]
