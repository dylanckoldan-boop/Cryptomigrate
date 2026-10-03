import datetime

import pytest

from cryptomigrate.discovery.policy import PolicyError, load_policy
from cryptomigrate.discovery.scanner import Scanner, apply_exceptions, redact

from .conftest import FIXTURES

POLICY = load_policy("des-to-aes")


@pytest.fixture(scope="module")
def findings():
    scanner = Scanner(POLICY, FIXTURES)
    return {(f.location, f.line): f for f in scanner.scan([FIXTURES])}


EXPECTED = [
    ("source/LegacyCrypto.java", 7, "CM-JAVA-001", "3DES", "CBC"),
    ("source/LegacyCrypto.java", 8, "CM-JAVA-001", "DES", None),
    ("source/LegacyCrypto.java", 9, "CM-JAVA-002", "3DES", None),
    ("source/legacy_crypto.py", 9, "CM-PY-001", "3DES", "CBC"),
    ("source/legacy_crypto.py", 2, "CM-PY-002", "3DES", None),
    ("source/legacy_crypto.py", 10, "CM-PY-003", "3DES", "CBC"),
    ("source/Legacy.cs", 4, "CM-NET-001", "3DES", None),
    ("source/Legacy.cs", 5, "CM-NET-001", "DES", None),
    ("source/legacy.go", 6, "CM-GO-001", "3DES", None),
    ("source/legacy.js", 2, "CM-JS-001", "3DES", "CBC"),
    ("source/legacy.js", 3, "CM-JS-002", "3DES", None),
    ("source/legacy.c", 3, "CM-C-001", "3DES", "CBC"),
    ("source/legacy.php", 2, "CM-PHP-001", "3DES", "CBC"),
    ("source/legacy.rb", 1, "CM-RUBY-001", "3DES", "CBC"),
    ("source/legacy.rs", 1, "CM-RUST-001", "3DES", None),
    ("source/legacy.sql", 1, "CM-SQL-001", "3DES", None),
    ("source/legacy.sql", 2, "CM-SQL-002", "3DES", None),
    ("source/legacy.sql", 3, "CM-SQL-001", "3DES", None),
    ("config/nginx.conf", 3, "CM-TLS-001", "3DES", None),
    ("config/httpd-ssl.conf", 1, "CM-TLS-001", "3DES", None),
    ("config/sshd_config", 2, "CM-SSH-001", "3DES", "CBC"),
    ("config/server.xml", 3, "CM-TLS-002", "3DES", "CBC"),
    ("config/application.properties", 1, "CM-GEN-001", "3DES", "ECB"),
    ("config/application.properties", 2, "CM-TLS-002", "3DES", "CBC"),
    ("config/ipsec.conf", 2, "CM-IPSEC-001", "3DES", None),
    ("config/krb5.conf", 2, "CM-KRB-001", "3DES", "CBC"),
    ("config/krb5.conf", 3, "CM-KRB-001", "DES", None),
    ("config/snmpd.conf", 1, "CM-SNMP-001", "DES", None),
    ("config/gpg.conf", 1, "CM-PGP-001", "3DES", None),
    ("config/router.cfg", 2, "CM-NETDEV-001", "3DES", None),
    ("config/router.cfg", 4, "CM-NETDEV-001", "3DES", None),
    ("config/router.cfg", 5, "CM-NETDEV-001", "DES", None),
    ("config/saml-sp.xml", 1, "CM-XML-001", "3DES", "CBC"),
    ("config/make-cert.sh", 1, "CM-PKCS12-001", "3DES", None),
]


@pytest.mark.parametrize("location,line,rule,algorithm,mode", EXPECTED)
def test_detects(findings, location, line, rule, algorithm, mode):
    f = findings[(location, line)]
    assert (f.rule_id, f.algorithm, f.mode) == (rule, algorithm, mode)
    assert f.severity == POLICY.rule(rule).severity_for(algorithm)


@pytest.mark.parametrize("location", ["source/Modern.java", "source/modern.py", "source/modern.js",
                                      "config/jetty.xml", "config/ssh_config"])
def test_no_false_positives(findings, location):
    assert not [f for (loc, _), f in findings.items() if loc == location]


def test_cipher_list_semantics(findings):
    assert findings[("config/nginx.conf", 7)].severity == "low"          # broad alias without !3DES
    assert ("config/nginx.conf", 11) not in findings                      # explicitly excludes 3DES
    assert findings[("config/nginx.conf", 3)].fixable


def test_one_finding_per_rule_per_line(findings):
    java = [f for (loc, _), f in findings.items() if loc == "source/LegacyCrypto.java"]
    assert len([f for f in java if f.line == 10]) == 1


def test_inline_suppression_recorded_not_dropped(findings):
    f = findings[("source/suppressed.py", 5)]
    assert f.suppressed and "published test vector" in f.suppression and not f.active


def test_file_level_suppression_and_rule_scoping(tmp_path):
    (tmp_path / "a.py").write_text("# cryptomigrate: ignore-file=CM-PY-002 -- legacy reader\nx = TripleDES(k)\n"
                                   "y = DES3.new(k, DES3.MODE_ECB)\n")
    found = {f.rule_id: f for f in Scanner(POLICY, tmp_path).scan([tmp_path])}
    assert found["CM-PY-002"].suppressed and found["CM-PY-002"].suppression == "legacy reader"
    assert not found["CM-PY-001"].suppressed


def test_ignore_file_and_excluded_dirs(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "x.py").write_text("DES3.new(k)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "y.js").write_text("crypto.createCipheriv('des-ede3-cbc', k, iv)\n")
    (tmp_path / "app.py").write_text("DES3.new(k)\n")
    scanner = Scanner(POLICY, tmp_path, exclude_dirs={"node_modules"}, ignore_patterns=["vendor/"])
    assert [f.location for f in scanner.scan([tmp_path])] == ["app.py"]


def test_utf16_registry_export(tmp_path):
    text = ("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168]\r\n\"Enabled\"=dword:ffffffff\r\n\r\n"
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\"
            "DES 56/56]\r\n\"Enabled\"=dword:00000000\r\n")
    (tmp_path / "schannel.reg").write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    found = Scanner(POLICY, tmp_path).scan([tmp_path])
    assert [(f.rule_id, f.algorithm) for f in found] == [("CM-WINREG-001", "3DES")]  # disabled DES not flagged


def test_exceptions_apply_until_expiry(tmp_path):
    (tmp_path / "vendor_sdk.py").write_text("DES3.new(k)\n")
    found = Scanner(POLICY, tmp_path).scan([tmp_path])
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    expired = apply_exceptions(found, [{"id": "EXC-1", "rule": "CM-PY-001", "path": "vendor_*", "expires": tomorrow}])
    assert found[0].exception == "EXC-1" and not expired
    found = Scanner(POLICY, tmp_path).scan([tmp_path])
    expired = apply_exceptions(found, [{"id": "EXC-2", "fingerprint": found[0].fingerprint, "expires": "2020-01-01"}])
    assert found[0].exception is None and expired[0]["id"] == "EXC-2"


def test_fingerprint_stable_when_lines_shift(tmp_path):
    (tmp_path / "a.py").write_text("DES3.new(k)\n")
    before = Scanner(POLICY, tmp_path).scan([tmp_path])[0].fingerprint
    (tmp_path / "a.py").write_text("import os\n\n\nDES3.new(k)\n")
    after = Scanner(POLICY, tmp_path).scan([tmp_path])[0]
    assert after.fingerprint == before and after.line == 4


def test_redaction_keeps_evidence_but_hides_keys():
    assert "<redacted-hex>" in redact('k = "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"')
    assert "<redacted>" in redact('key = "q83vEjRWeJq83vEjRWeJAbCdEfGh1234567890+/"')
    assert redact('Cipher.getInstance("DESede/CBC/PKCS5Padding")') == 'Cipher.getInstance("DESede/CBC/PKCS5Padding")'


def test_invalid_policy_pattern_reports_rule(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\nname: x\ntarget_algorithm: AES-256-GCM\nrules:\n  - {id: R1, pattern: '(', files: ['*']}\n")
    with pytest.raises(PolicyError, match="R1"):
        load_policy(str(bad))


def test_iana_names_with_lowercase_anon(tmp_path):
    suites = "TLS_AES_128_GCM_SHA256,TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
    (tmp_path / "server.xml").write_text(f'<Connector ciphers="{suites}"/>\n')
    assert [f.rule_id for f in Scanner(POLICY, tmp_path).scan([tmp_path])] == ["CM-TLS-002"]
