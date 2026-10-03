"""Security layers: TLS/PKI, authentication & wireless, secure coding, binaries, malware, governance."""

import datetime as dt
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
from importlib import resources
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cryptomigrate.cli import main
from cryptomigrate.config import build_config, load_config
from cryptomigrate.discovery.binaries import check_elf, scan_binaries
from cryptomigrate.discovery.certs import analyze_certificate, cabf_max_validity, load_certificates
from cryptomigrate.discovery.policy import load_policy_set
from cryptomigrate.discovery.run import run_discovery
from cryptomigrate.discovery.scanner import Scanner
from cryptomigrate.discovery.tlsassess import assess_endpoint
from cryptomigrate.malware import MalwareScanError, ping, scan_bytes
from cryptomigrate.reporting.formats import to_cbom

LAYERS = ["pki-tls", "auth-wireless", "secure-coding"]
POLICY = load_policy_set("des-to-aes", LAYERS)
FIXTURES = Path(__file__).parent / "fixtures"
NOW = dt.datetime.now(dt.timezone.utc)
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"  # split: keep AV calm

SAMPLES = {
    "app/db.py": ('cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
                  'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
                  "requests.get(url, verify=False)\n"
                  "digest = hashlib.md5(password.encode()).hexdigest()\n"
                  'DB_PASSWORD = "Winter2024!"\n'
                  "kek = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600000).derive(password)\n"),
    "app/Dao.java": ("ResultSet r = stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
                     'PreparedStatement p = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
                     'KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\ng.initialize(1024);\n'),
    "app/view.php": '<?php $r = mysqli_query($db, "SELECT * FROM t WHERE id = " . $_GET["id"]);\n',
    "app/repo.ts": ("await db.query(`SELECT * FROM t WHERE id = ${id}`);\n"
                    "const agent = new https.Agent({ rejectUnauthorized: false });\n"),
    "native/copy.c": ('#include <string.h>\nvoid f(char *in) { char b[16]; strcpy(b, in); gets(b); scanf("%s", b); '
                      'snprintf(b, sizeof b, "%s", in); }\nvoid g(char *b) { scanf("%15s", b); }\n'),
    "native/Makefile": "CFLAGS += -O2 -fno-stack-protector\nLDFLAGS += -z execstack\n",
    "etc/nginx.conf": "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n",
    "etc/httpd.conf": "SSLProtocol all -SSLv3\n",
    "etc/main.cf": "smtpd_tls_protocols = !SSLv2, !SSLv3\n",
    "etc/haproxy.cfg": "global\n    ssl-default-bind-options ssl-min-ver TLSv1.0 no-tls-tickets\n",
    "etc/openssl.cnf": "[system_default_sect]\nMinProtocol = TLSv1\n",
    "etc/app.properties": "https.protocols=TLSv1,TLSv1.1,TLSv1.2\n",
    "etc/modern.conf": "ssl_protocols TLSv1.2 TLSv1.3;\n",
    "wifi/hostapd.conf": "wpa=3\nwpa_pairwise=TKIP CCMP\nieee80211w=0\nwps_state=2\n",
    "wifi/wpa_supplicant.conf": ('network={\n    ssid="corp"\n    eap=PEAP\n    phase2="auth=MSCHAPV2"\n}\n'
                                 'network={\n    ssid="corp-ok"\n    eap=PEAP\n    phase2="auth=MSCHAPV2"\n'
                                 '    ca_cert="/etc/ca.pem"\n    domain_suffix_match="radius.example.com"\n}\n'),
    "etc/shadow": "root:!:19000:0:99999:7:::\nlegacy:abJnggxhB/yWI:19000:0:99999:7:::\nmodern:$6$s$h:19000::::::\n",
    "web/.htpasswd": "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\nbob:$apr1$abc$def\ncarol:$2y$12$abcdefghijklmnopqrstuv\n",
    "vpn/options.pptpd": "require-mschap-v2\nrequire-mppe-128\n",
    "keys/server.key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
}
EXPECTED = {
    ("app/db.py", 1, "SQLI-PY-001", "high"), ("app/db.py", 3, "TLS-VERIFY-001", "high"),
    ("app/db.py", 4, "AUTH-HASH-001", "medium"), ("app/db.py", 5, "AUTH-CRED-001", "high"),
    ("app/Dao.java", 1, "SQLI-JAVA-001", "high"), ("app/Dao.java", 3, "TLS-RSA-001", "high"),
    ("app/view.php", 1, "SQLI-PHP-001", "high"), ("app/repo.ts", 1, "SQLI-JS-001", "high"),
    ("app/repo.ts", 2, "TLS-VERIFY-001", "high"), ("native/copy.c", 2, "MEM-C-001", "critical"),
    ("native/copy.c", 2, "MEM-C-002", "high"), ("native/copy.c", 2, "MEM-C-003", "high"),
    ("native/Makefile", 1, "MEM-BUILD-001", "high"), ("native/Makefile", 2, "MEM-BUILD-001", "high"),
    ("etc/nginx.conf", 1, "TLS-PROTO-001", "high"), ("etc/httpd.conf", 1, "TLS-PROTO-001", "high"),
    ("etc/main.cf", 1, "TLS-PROTO-001", "high"), ("etc/haproxy.cfg", 2, "TLS-PROTO-001", "high"),
    ("etc/openssl.cnf", 2, "TLS-PROTO-001", "high"), ("etc/app.properties", 1, "TLS-PROTO-001", "high"),
    ("wifi/hostapd.conf", 1, "WIFI-WPA1-001", "high"), ("wifi/hostapd.conf", 2, "WIFI-TKIP-001", "high"),
    ("wifi/hostapd.conf", 3, "WIFI-PMF-001", "medium"), ("wifi/hostapd.conf", 4, "WIFI-WPS-001", "medium"),
    ("wifi/wpa_supplicant.conf", 1, "WIFI-EAP-001", "high"), ("etc/shadow", 2, "AUTH-CRYPT-001", "critical"),
    ("web/.htpasswd", 1, "AUTH-HTPASSWD-001", "high"), ("web/.htpasswd", 2, "AUTH-HTPASSWD-001", "medium"),
    ("vpn/options.pptpd", 1, "AUTH-MSCHAP-001", "high"), ("keys/server.key", 1, "TLS-KEY-001", "critical"),
    ("win/lsa.reg", 4, "AUTH-NTLM-001", "high"), ("win/lsa.reg", 5, "AUTH-NTLM-002", "critical"),
}


@pytest.fixture
def sample_repo(tmp_path):
    for rel, text in SAMPLES.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    reg = ('Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa]\r\n'
           '"LmCompatibilityLevel"=dword:00000002\r\n"NoLMHash"=dword:00000000\r\n')
    (tmp_path / "win").mkdir()
    (tmp_path / "win" / "lsa.reg").write_bytes(b"\xff\xfe" + reg.encode("utf-16-le"))
    return tmp_path


def test_layer_rules_detect_exactly_the_expected_weaknesses(sample_repo):
    found = Scanner(POLICY, sample_repo).scan([sample_repo])
    got = {(f.location, f.line, f.rule_id, f.severity) for f in found if f.layer != "des-to-aes"}
    assert got == EXPECTED, {"missing": EXPECTED - got, "unexpected": got - EXPECTED}
    by_key = {(f.location, f.rule_id): f for f in found}
    assert "Winter2024" not in by_key[("app/db.py", "AUTH-CRED-001")].snippet  # secrets redacted
    assert "abJnggxhB" not in by_key[("etc/shadow", "AUTH-CRYPT-001")].snippet
    assert by_key[("etc/shadow", "AUTH-CRYPT-001")].algorithm == "DES"
    assert by_key[("app/db.py", "AUTH-HASH-001")].algorithm == "MD5"
    assert {f.layer for f in found} == {"pki-tls", "auth-wireless", "secure-coding"}


def test_tls_protocol_remediation_is_safe_and_complete(sample_repo):
    from cryptomigrate.remediation import apply_remediation, plan_remediation

    cfg = build_config({"layers": LAYERS}, sample_repo)
    inventory = run_discovery(cfg, POLICY, probe_tls=False, profile_data=False)
    changes, manual = plan_remediation(cfg, POLICY, inventory["findings"], only_rules={"TLS-PROTO-001"})
    apply_remediation(cfg, changes)
    read = lambda rel: (sample_repo / rel).read_text()  # noqa: E731
    assert read("etc/nginx.conf") == "ssl_protocols TLSv1.2;\n"
    assert read("etc/httpd.conf") == "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
    assert read("etc/main.cf") == "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n"
    assert "ssl-min-ver TLSv1.2 no-tls-tickets" in read("etc/haproxy.cfg")
    assert read("etc/openssl.cnf").endswith("MinProtocol = TLSv1.2\n")
    assert read("etc/app.properties") == "https.protocols=TLSv1.2\n"
    rescan = run_discovery(cfg, POLICY, probe_tls=False, profile_data=False)
    assert not [f for f in rescan["findings"] if f["rule_id"] == "TLS-PROTO-001"]


# ------------------------------------------------------------------ certificates
def _cert(cn, key, issuer=None, issuer_key=None, days=90, start=None, san=True, ca=False, sign_hash=hashes.SHA256()):
    start = start or NOW - dt.timedelta(days=1)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(start)
               .not_valid_after(start + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(issuer_key or key, sign_hash)


def _rules(cert):
    return {f.rule_id for f in analyze_certificate(cert, POLICY, "x.pem", "file")[0]}


def test_certificate_checks():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Example CA", ca_key, ca=True, days=3650)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    assert _rules(_cert("app.example", leaf_key, ca.subject, ca_key)) == set()
    assert _rules(ca) == set()  # trust anchors are exempt
    weak = _cert("legacy.example", rsa.generate_private_key(public_exponent=65537, key_size=1024), days=365,
                 start=NOW - dt.timedelta(days=400), san=False)
    assert _rules(weak) == {"CERT-KEY-001", "CERT-EXP-001", "CERT-SELF-001", "CERT-SAN-001"}
    sha1 = load_certificates((FIXTURES / "certs" / "sha1-legacy.pem").read_bytes())[0]
    assert "CERT-SIG-001" in _rules(sha1)
    issued_2026 = _cert("long.example", leaf_key, ca.subject, ca_key, days=365, start=dt.datetime(2026, 4, 1, tzinfo=dt.timezone.utc))
    issued_2025 = _cert("old.example", leaf_key, ca.subject, ca_key, days=365, start=dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc))
    assert "CERT-LIFE-001" in _rules(issued_2026) and "CERT-LIFE-001" not in _rules(issued_2025)
    assert [cabf_max_validity(dt.date(y, m, 20)) for y, m in ((2025, 1), (2026, 3), (2027, 3), (2029, 3))] == [398, 200, 100, 47]


# ------------------------------------------------------------------ TLS handshake assessment
@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert("localhost", key, days=30, ca=False)
    d = tmp_path_factory.mktemp("tls")
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                  serialization.NoEncryption()))
    return d


def _serve(handler) -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)

    def loop():
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return sock.getsockname()[1]


def test_tls_assessment_modern_server(tls_material):
    def handler(conn):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_material / "cert.pem", tls_material / "key.pem")
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass

    port = _serve(handler)
    untrusted = assess_endpoint(f"localhost:{port}", timeout=3)
    assert untrusted["legacy_protocols"] == [] and untrusted["verified"] is False
    assert untrusted["protocol"] in ("TLSv1.2", "TLSv1.3") and untrusted["forward_secrecy"] is True
    assert untrusted["certificate_der"]
    trusted = assess_endpoint(f"localhost:{port}", ca_bundle=str(tls_material / "cert.pem"), timeout=3)
    assert trusted["verified"] is True
    mismatch = assess_endpoint(f"127.0.0.1:{port}", ca_bundle=str(tls_material / "cert.pem"), timeout=3)
    assert mismatch["verified"] is False and "mismatch" in mismatch["verify_error"].lower()


def test_tls_assessment_detects_tls10_only_server(tls_material):
    tlslite = pytest.importorskip("tlslite.api")
    chain = tlslite.X509CertChain()
    chain.parsePemList((tls_material / "cert.pem").read_text())
    private = tlslite.parsePEMKey((tls_material / "key.pem").read_text(), private=True)

    def handler(conn):
        settings = tlslite.HandshakeSettings()
        settings.minVersion, settings.maxVersion = (3, 1), (3, 1)
        if hasattr(settings, "versions"):
            settings.versions = [(3, 1)]  # tlslite-ng: the explicit version list wins over min/max
        try:
            tlslite.TLSConnection(conn).handshakeServer(certChain=chain, privateKey=private, settings=settings)
        except Exception:  # noqa: BLE001
            pass
        finally:
            conn.close()

    result = assess_endpoint(f"localhost:{_serve(handler)}", timeout=3)
    assert "TLSv1.0" in result["legacy_protocols"] and "SSLv3" not in result["legacy_protocols"]
    assert result["modern_error"] and not result["protocol"]


def test_discovery_turns_assessments_into_findings_and_cbom(tls_material, tmp_path):
    def handler(conn):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_material / "cert.pem", tls_material / "key.pem")
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass

    endpoint = f"localhost:{_serve(handler)}"
    (tmp_path / "certs").mkdir()
    shutil.copy(FIXTURES / "certs" / "sha1-legacy.pem", tmp_path / "certs" / "legacy.pem")
    cfg = build_config({"layers": LAYERS, "scan": {"tls_endpoints": [endpoint]}}, tmp_path)
    inventory = run_discovery(cfg, POLICY, profile_data=False)
    rules = {f["rule_id"] for f in inventory["findings"]}
    assert {"TLS-PROBE-CERT-001", "CERT-SELF-001", "CERT-SIG-001"} <= rules
    assert inventory["tls_assessments"][0]["protocol"] in ("TLSv1.2", "TLSv1.3")
    bom = to_cbom(inventory, POLICY)
    kinds = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert {"certificate", "protocol", "algorithm"} <= kinds
    validation = pytest.importorskip("cyclonedx.validation.json")
    schema = pytest.importorskip("cyclonedx.schema")
    import json
    assert validation.JsonStrictValidator(schema.SchemaVersion.V1_6).validate_str(json.dumps(bom)) is None


# ------------------------------------------------------------------ binaries (checksec)
def test_hardened_system_binary():
    report = check_elf(Path("/bin/ls"))  # (Debian/Ubuntu build the python3 binary itself without PIE, by design)
    assert report["nx"] and report["pie"] and report["relro"] == "full" and report["canary"]
    assert check_elf(Path(sys.executable).resolve())["kind"] == "executable"


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not available")
def test_binary_hardening_flags_are_verified(tmp_path):
    source = tmp_path / "prog.c"
    source.write_text('#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) { char buf[32]; '
                      'strcpy(buf, argc > 1 ? argv[1] : "x"); puts(buf); return 0; }\n')
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-z", "execstack", "-no-pie", "-Wl,-z,norelro", "-o",
                    str(tmp_path / "bin" / "insecure"), str(source)], check=True,
                   capture_output=True) if (tmp_path / "bin").mkdir() is None else None
    subprocess.run(["gcc", "-O2", "-D_FORTIFY_SOURCE=3", "-fstack-protector-all", "-fPIE", "-pie",
                    "-Wl,-z,relro,-z,now", "-o", str(tmp_path / "bin" / "hardened"), str(source)], check=True,
                   capture_output=True)
    scanner = Scanner(POLICY, tmp_path)
    findings, reports = scan_binaries([tmp_path / "bin"], POLICY, scanner)
    by_binary = {}
    for f in findings:
        by_binary.setdefault(f.location, set()).add(f.rule_id)
    assert by_binary.get("bin/insecure") == {"MEM-BIN-NX-001", "MEM-BIN-PIE-001", "MEM-BIN-RELRO-001",
                                              "MEM-BIN-CANARY-001", "MEM-BIN-FORTIFY-001"}
    assert "bin/hardened" not in by_binary
    assert {r["location"]: r["relro"] for r in reports} == {"bin/hardened": "full", "bin/insecure": "none"}


# ------------------------------------------------------------------ malware hook
@pytest.fixture
def clamd():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def handle(conn):
        with conn:
            data = b""
            while b"\0" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk
            command, _, buf = data.partition(b"\0")
            if command == b"zPING":
                conn.sendall(b"PONG\0")
                return
            payload = b""
            while True:
                while len(buf) < 4:
                    buf += conn.recv(65536)
                size = struct.unpack("!I", buf[:4])[0]
                buf = buf[4:]
                if size == 0:
                    break
                while len(buf) < size:
                    buf += conn.recv(65536)
                payload, buf = payload + buf[:size], buf[size:]
            infected = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in payload
            conn.sendall(b"stream: Eicar-Test-Signature FOUND\0" if infected else b"stream: OK\0")

    def loop():
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return f"tcp:127.0.0.1:{sock.getsockname()[1]}"


def test_clamd_client(clamd):
    assert ping(clamd) and scan_bytes(b"quarterly report", clamd) is None
    assert scan_bytes(EICAR * 3000, clamd, chunk_size=4096) == "Eicar-Test-Signature"  # multi-chunk stream
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = f"tcp:127.0.0.1:{s.getsockname()[1]}"
    with pytest.raises(MalwareScanError):
        scan_bytes(b"x", closed, timeout=2)


def test_engine_quarantines_malware_found_while_decrypting(tmp_path, kek, clamd):
    from cryptomigrate.keys.keystore import Keystore
    from cryptomigrate.migration.engine import MigrationEngine

    from .conftest import LEGACY_KEY, build_legacy_project, legacy_encrypt

    path = build_legacy_project(tmp_path / "p")
    infected = tmp_path / "p" / "archive" / "invoice.enc"
    infected.write_bytes(legacy_encrypt(EICAR, encoding="raw"))
    data = yaml.safe_load(path.read_text())
    data["migration"] = {"malware_scan": {"enabled": True, "clamd": clamd, "timeout_s": 5}}
    path.write_text(yaml.safe_dump(data))
    cfg = load_config(path)
    store = Keystore.from_config(cfg, create=True)
    store.generate()
    store.import_legacy("legacy-3des", "3DES", LEGACY_KEY)
    run = MigrationEngine(cfg, store).run(cfg.source("archive"))
    assert run["counters"]["malware"] == 1 and run["counters"]["would_migrate"] == 3
    assert "Eicar-Test-Signature" in run["errors"][0]["error"]
    assert any(e["event"] == "malware.detected" for e in store.audit.entries())


# ------------------------------------------------------------------ governance: dual control, signed sign-offs
def test_dual_control_for_key_destruction(project, capsys):
    cfg, _ = project
    data = yaml.safe_load(cfg.path.read_text())
    data["governance"]["dual_control"] = True
    cfg.path.write_text(yaml.safe_dump(data))
    assert main(["--config", str(cfg.path), "reencrypt", "--apply"]) == 0
    destroy = ["--config", str(cfg.path), "keys", "destroy", "--key-id", "legacy-3des", "--confirm", "legacy-3des",
               "--reason", "closeout"]
    assert main(destroy) == 2 and "dual control" in capsys.readouterr().err
    data["governance"]["approvals"] = {"key_destruction": [{"by": "CISO"}, {"by": "Key custodian"}]}
    cfg.path.write_text(yaml.safe_dump(data))
    assert main(destroy) == 0


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_signoffs_require_signed_commits(tmp_path):
    from cryptomigrate.gates import evaluate_gate

    data = yaml.safe_load(resources.files("cryptomigrate.templates").joinpath("migration.yaml").read_text())
    data["project"].update(name="X", organization="Y", sponsor="S", project_manager="P", security_lead="L",
                           target_completion="2027-01-31")
    data["governance"].update(signoffs={"charter": {"by": "S", "date": "2026-10-01"}}, require_signed_commits=True)
    (tmp_path / "migration.yaml").write_text(yaml.safe_dump(data))
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([*git, "add", "migration.yaml"], cwd=tmp_path, check=True)
    subprocess.run([*git, "commit", "-qm", "charter"], cwd=tmp_path, check=True)
    signoff = next(c for c in evaluate_gate(load_config(tmp_path / "migration.yaml"), 1)["criteria"]
                   if c["id"] == "P1-SIGNOFF")
    assert signoff["status"] == "fail" and "signature N" in signoff["evidence"]


def test_layer_gates_block_only_at_threshold(tmp_path):
    from cryptomigrate.gates import evaluate_gate
    from cryptomigrate.util import write_json

    cfg = build_config({"layers": LAYERS}, tmp_path)

    def inventory(severity):
        return {"generated": "2026-10-02T00:00:00Z", "policy": {"id": "des-to-aes"}, "summary": {"by_category": {}},
                "findings": [{"rule_id": "SQLI-PY-001", "category": "source", "severity": severity,
                              "layer": "secure-coding", "location": "a.py"}]}

    write_json(cfg.artifact("inventory.json"), inventory("high"))
    status = {c["id"]: c["status"] for c in evaluate_gate(cfg, 4)["criteria"]}
    assert status["P4-LAYERS"] == "fail" and status["P4-CODE"] == "pass"
    write_json(cfg.artifact("inventory.json"), inventory("medium"))
    assert {c["id"]: c["status"] for c in evaluate_gate(cfg, 4)["criteria"]}["P4-LAYERS"] == "pass"


def test_doctor_reports_private_state(project):
    from cryptomigrate.doctor import run_doctor

    cfg, _ = project
    checks = {c["id"]: c["status"] for c in run_doctor(cfg)}
    assert checks["DOC-KEYSTORE-PERMS"] == "pass" and checks["DOC-STATE-PERMS"] == "pass"
    assert checks["DOC-KEK"] == "pass" and checks["DOC-PYTHON"] == "pass"
