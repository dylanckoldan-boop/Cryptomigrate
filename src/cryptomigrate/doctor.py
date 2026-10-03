"""Host hardening preflight for migration operators (`cryptomigrate doctor`).

The migration host holds keys and briefly sees plaintext, so it gets the same scrutiny as the data. Checks:
supported Python/OpenSSL, FIPS mode, least privilege, core dumps disabled, KEK delivered by environment,
keystore/state/audit permissions, keystore not tracked by Git, malware scanner and CA bundle reachable.
"""

from __future__ import annotations

import os
import platform
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import Config


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def run_doctor(cfg: Config) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(check_id: str, title: str, status: str, detail: str = "") -> None:
        checks.append({"id": check_id, "title": title, "status": status, "detail": detail})

    add("DOC-PYTHON", "Supported Python (3.10+)", "pass" if sys.version_info >= (3, 10) else "fail",
        platform.python_version())
    try:
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend

        openssl = backend.openssl_version_text()
        version = f"cryptography {cryptography.__version__}, {openssl}"
    except Exception:  # noqa: BLE001
        openssl, version = "unknown", "unknown"
    add("DOC-OPENSSL", "Maintained OpenSSL (3.x) under pyca/cryptography",
        "warn" if openssl.startswith(("OpenSSL 1.", "OpenSSL 0.")) else "pass", version)
    fips = Path("/proc/sys/crypto/fips_enabled")
    if fips.exists():
        enabled = fips.read_text().strip() == "1"
        add("DOC-FIPS", "Kernel FIPS mode", "pass" if enabled else "info",
            "enabled" if enabled else "disabled (needed only where FIPS 140-3 validated operation is mandated)")
    if hasattr(os, "geteuid"):
        root = os.geteuid() == 0
        add("DOC-ROOT", "Not running as root (least privilege)", "warn" if root else "pass",
            "use a dedicated service account" if root else "")
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_CORE)
        add("DOC-CORE", "Core dumps disabled (keys cannot leak into core files)", "pass" if soft == 0 else "warn",
            f"RLIMIT_CORE={soft}")
    except ImportError:
        pass
    sources = [cfg.kek_env, cfg.kek_passphrase_env, cfg.keystore_wrap.get("rsa_private_key_env") or ""]
    add("DOC-KEK", "Key-encryption key delivered via the environment / secrets manager",
        "pass" if any(name and os.environ.get(name) for name in sources) else "warn", "never pass keys as arguments")
    if cfg.keystore_path.exists():
        mode = _mode(cfg.keystore_path)
        add("DOC-KEYSTORE-PERMS", "Keystore readable by its owner only (0600)",
            "pass" if not mode & 0o077 else "fail", oct(mode))
    if cfg.state_dir.exists():
        mode = _mode(cfg.state_dir)
        add("DOC-STATE-PERMS", "State directory private (0700)", "pass" if not mode & 0o077 else "warn", oct(mode))
    if cfg.audit_path.exists():
        mode = _mode(cfg.audit_path)
        add("DOC-AUDIT-PERMS", "Audit log not writable by others", "pass" if not mode & 0o022 else "fail", oct(mode))
    if (cfg.root / ".git").exists():
        try:
            tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(cfg.keystore_path)], cwd=cfg.root,
                                     capture_output=True, timeout=10).returncode == 0
            ignored = subprocess.run(["git", "check-ignore", "-q", str(cfg.state_dir)], cwd=cfg.root,
                                     capture_output=True, timeout=10).returncode == 0
            add("DOC-GIT-KEYSTORE", "Keystore not tracked by Git (destruction needs it)", "fail" if tracked else "pass")
            add("DOC-GIT-IGNORE", "State directory is git-ignored", "pass" if ignored else "warn", str(cfg.state_dir))
        except (OSError, subprocess.TimeoutExpired) as exc:
            add("DOC-GIT", "Git checks", "warn", str(exc))
    if cfg.malware.get("enabled"):
        from .malware import ping

        address = str(cfg.malware.get("clamd", ""))
        add("DOC-CLAMD", "Malware scanner (clamd) reachable", "pass" if ping(address) else "fail", address)
    if cfg.tls_ca_bundle:
        add("DOC-CA-BUNDLE", "TLS CA bundle readable", "pass" if cfg.tls_ca_bundle.is_file() else "fail",
            str(cfg.tls_ca_bundle))
    return checks
