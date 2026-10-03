"""Wire-level TLS probe against real TLS stacks: modern OpenSSL (refuses DES) and tlslite-ng (still speaks 3DES)."""

import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cryptomigrate.discovery.tlsprobe import DES_SUITES, build_client_hello, parse_endpoint, probe


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    d = tmp_path_factory.mktemp("tls")
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    (d / "c.pem").write_text(cert_pem)
    (d / "k.pem").write_text(key_pem)
    return d / "c.pem", d / "k.pem", cert_pem, key_pem


def serve(handler) -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def loop():
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return sock.getsockname()[1]


def test_client_hello_offers_only_des_suites():
    hello = build_client_hello("example.com")
    assert hello[0] == 0x16 and hello[5] == 0x01  # handshake record, ClientHello
    suites_len = int.from_bytes(hello[44:46], "big")
    offered = {int.from_bytes(hello[46 + i:48 + i], "big") for i in range(0, suites_len, 2)}
    assert offered - {0x00FF} == set(DES_SUITES)
    assert b"example.com" in hello


def test_parse_endpoint():
    assert parse_endpoint("host:8443") == ("host", 8443)
    assert parse_endpoint("[::1]:443") == ("::1", 443)
    assert parse_endpoint("host") == ("host", 443)


def test_modern_openssl_server_refuses(cert):
    cert_path, key_path, *_ = cert

    def handler(conn):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.set_ciphers("ECDHE+AESGCM")
        try:
            ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    result = probe(f"127.0.0.1:{serve(handler)}")
    assert result.status == "not-accepted" and "handshake_failure" in result.detail  # parsed, not decode_error


def test_3des_server_detected(cert):
    tlslite = pytest.importorskip("tlslite.api")
    *_, cert_pem, key_pem = cert
    chain = tlslite.X509CertChain()
    chain.parsePemList(cert_pem)
    private = tlslite.parsePEMKey(key_pem, private=True)

    def handler(conn):
        settings = tlslite.HandshakeSettings()
        settings.cipherNames = ["3des"]
        try:
            tlslite.TLSConnection(conn).handshakeServer(certChain=chain, privateKey=private, settings=settings)
        except Exception:  # noqa: BLE001 - the probe aborts after ServerHello
            pass
        finally:
            conn.close()

    result = probe(f"localhost:{serve(handler)}")
    assert result.status == "accepted"
    assert result.cipher.endswith("3DES_EDE_CBC_SHA") and result.protocol == "TLSv1.2"


def test_unreachable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert probe(f"127.0.0.1:{port}", timeout=2).status == "unreachable"
