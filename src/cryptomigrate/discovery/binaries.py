"""Binary-hardening layer: checksec-style verification of ELF executables and shared objects.

Buffer-overflow exploitation is blocked most cheaply by compiler and linker mitigations, which are either present
in the shipped binary or not. This module reads ELF headers directly (no external tools) and reports:

    NX        non-executable stack (PT_GNU_STACK without PF_X)
    PIE       position-independent executable, so ASLR can randomise the image base
    RELRO     read-only relocations; "full" when BIND_NOW is also set
    Canary    stack-smashing protector (__stack_chk_fail referenced)
    FORTIFY   glibc _FORTIFY_SOURCE checked functions (__*_chk) referenced

Go and Rust binaries are memory-safe by construction, so canary/FORTIFY checks are skipped for them.
Windows PE binaries are out of scope (use Microsoft BinSkim).
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from .scanner import Finding, fingerprint

PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 2, 3, 0x6474E551, 0x6474E552
DT_NULL, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 0, 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000
PF_X = 0x1
MAX_BINARY = 512 * 1024 * 1024
_FORTIFIED = re.compile(rb"__[a-z0-9_]+_chk\x00")


def check_elf(path: Path) -> dict[str, Any] | None:
    """Hardening report for an ELF file, or None if ``path`` is not ELF."""
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                return None
        if path.stat().st_size > MAX_BINARY:
            return {"error": "file too large"}
        data = path.read_bytes()
    except OSError as exc:
        return {"error": str(exc)}
    try:
        return _parse(data)
    except (struct.error, IndexError, ValueError) as exc:
        return {"error": f"malformed ELF: {exc}"}


def _parse(data: bytes) -> dict[str, Any]:
    is64, end = data[4] == 2, "<" if data[5] == 1 else ">"
    header = struct.unpack_from(end + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"), data, 16)
    e_type, phoff, phentsize, phnum = header[0], header[4], header[8], header[9]
    segments = []
    for i in range(phnum):
        offset = phoff + i * phentsize
        if is64:
            p_type, p_flags, p_offset, _va, _pa, p_filesz, _ms, _al = struct.unpack_from(end + "IIQQQQQQ", data, offset)
        else:
            p_type, p_offset, _va, _pa, p_filesz, _ms, p_flags, _al = struct.unpack_from(end + "IIIIIIII", data, offset)
        segments.append((p_type, p_flags, p_offset, p_filesz))
    types = {s[0] for s in segments}
    stack = next((s for s in segments if s[0] == PT_GNU_STACK), None)
    dynamic = next((s for s in segments if s[0] == PT_DYNAMIC), None)
    bind_now = pie_flag = False
    if dynamic:
        size, fmt = (16, end + "qQ") if is64 else (8, end + "iI")
        for offset in range(dynamic[2], dynamic[2] + dynamic[3] - size + 1, size):
            tag, value = struct.unpack_from(fmt, data, offset)
            if tag == DT_NULL:
                break
            if tag == DT_BIND_NOW or (tag == DT_FLAGS and value & DF_BIND_NOW):
                bind_now = True
            elif tag == DT_FLAGS_1:
                bind_now = bind_now or bool(value & DF_1_NOW)
                pie_flag = bool(value & DF_1_PIE)
    if e_type == 2:
        kind, pie = "executable", False
    elif e_type == 3:
        kind = "executable" if (PT_INTERP in types or pie_flag) else "shared-object"
        pie = True if kind == "executable" else None
    else:
        kind, pie = "other", None
    if b"Go build ID" in data or b"runtime.gopanic" in data:
        language = "go"
    elif b"rust_panic" in data or b"/rustc/" in data:
        language = "rust"
    else:
        language = "c/c++"
    relro = ("full" if bind_now else "partial") if PT_GNU_RELRO in types else "none"
    return {"kind": kind, "class": 64 if is64 else 32, "language": language, "static": dynamic is None,
            "nx": stack is not None and not stack[1] & PF_X, "stack_header": stack is not None, "pie": pie,
            "relro": relro, "canary": b"__stack_chk_fail" in data, "fortify": bool(_FORTIFIED.search(data))}


def scan_binaries(paths: list[Path], policy, scanner) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    reports: list[dict[str, Any]] = []
    ignored = scanner.stats["files_ignored"]
    for path, rel in scanner.walk(paths):
        report = check_elf(path)
        if report is None:
            continue
        report["location"] = rel
        reports.append(report)
        if "error" in report or report["kind"] == "other":
            continue

        def add(rule_id: str, detail: str, severity: str | None = None, report=report, rel=rel) -> None:
            rule = policy.rule(rule_id)
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, category="binary", algorithm="n/a",
                severity=severity or rule.severity_for(None), confidence=rule.confidence, location=rel,
                detail=detail, fingerprint=fingerprint(rule.id, rel, ""), cwe=list(rule.cwe),
                remediation=rule.remediation, layer=rule.pack, evidence={"origin": "file", **report}))

        if not report["nx"]:
            add("MEM-BIN-NX-001", "executable stack" if report["stack_header"] else
                "no PT_GNU_STACK header (stack may be executable)")
        if report["kind"] == "executable" and report["pie"] is False:
            add("MEM-BIN-PIE-001", "not position-independent (ASLR cannot randomise the image base)")
        if not report["static"] and report["relro"] != "full":
            add("MEM-BIN-RELRO-001", f"{report['relro']} RELRO", "low" if report["relro"] == "partial" else None)
        if report["language"] == "c/c++":
            if not report["canary"]:
                add("MEM-BIN-CANARY-001", "no stack canary (__stack_chk_fail not referenced)")
            if not report["fortify"]:
                add("MEM-BIN-FORTIFY-001", "no _FORTIFY_SOURCE checked functions referenced")
    scanner.stats["files_ignored"] = ignored
    return findings, reports
