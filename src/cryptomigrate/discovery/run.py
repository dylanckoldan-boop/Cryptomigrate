"""Phase 2 orchestration: build the cryptographic and security inventory from every discovery channel.

Channels: source/config scanning (the migration policy pack plus any enabled security layers), certificate files,
wire-level TLS probes and handshake assessment, ELF binary hardening, data-at-rest profiling, and the manual
inventory (HSMs, embedded devices, third-party systems that no scanner can see - risks R-01/R-02/R-05). Findings
are mapped to owning systems so ownership gaps show up as Phase 2 exit-criteria failures.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from cryptography import x509

from .. import __version__
from ..config import Config
from ..util import isotime
from .binaries import scan_binaries
from .certs import analyze_certificate, scan_certificate_files
from .dataprofile import profile_sources
from .policy import Policy
from .scanner import Finding, Scanner, apply_exceptions, fingerprint, load_ignore_patterns
from .tlsassess import assess_endpoint
from .tlsprobe import probe_all

INVENTORY_SCHEMA = "cryptomigrate-inventory/1"


def _synthetic(policy: Policy, rule_id: str, location: str, algorithm: str, detail: str, system: str | None = None,
               category: str = "protocol", evidence: dict | None = None) -> Finding:
    rule = policy.rule(rule_id)
    return Finding(rule_id=rule.id, title=rule.title, category=category, algorithm=algorithm,
                   severity=rule.severity_for(algorithm), confidence=rule.confidence, location=location, detail=detail,
                   fingerprint=fingerprint(rule.id, location, detail), system=system, cwe=list(rule.cwe),
                   cve=list(rule.cve), remediation=rule.remediation, layer=rule.pack, evidence=evidence or {})


def _manual_findings(cfg: Config, policy: Policy) -> list[Finding]:
    out = []
    for asset in cfg.manual_assets:
        if str(asset.get("status", "")).lower() == "remediated":
            continue  # owner confirmed the AES cut-over (record the evidence ticket in the asset's notes)
        algorithm = policy.normalize(str(asset.get("algorithm", ""))) or str(asset.get("algorithm", "3DES")).upper()
        finding = _synthetic(policy, "CM-MANUAL-001", f"manual:{asset.get('name', 'unnamed asset')}", algorithm,
                             f"{asset.get('type', 'other')}; AES support: {asset.get('aes_support', 'unknown')}",
                             asset.get("system"), "manual", dict(asset))
        finding.mode = str(asset["mode"]).upper() if asset.get("mode") else None
        out.append(finding)
    return out


def _des_probe_findings(cfg: Config, policy: Policy, endpoints: list[str]) -> tuple[list[Finding], list[dict]]:
    findings = []
    results = probe_all(endpoints)
    for result in results:
        if result.status != "accepted":
            continue
        system = cfg.system_for_endpoint(result.endpoint)
        finding = _synthetic(policy, "CM-PROBE-TLS-001", result.endpoint,
                             "3DES" if "3DES" in (result.cipher or "") else "DES",
                             f"negotiated {result.cipher} over {result.protocol}", system.id if system else None,
                             evidence=result.to_dict())
        finding.mode = "CBC"
        findings.append(finding)
    return findings, [r.to_dict() for r in results]


def _tls_assessments(cfg: Config, policy: Policy, endpoints: list[str],
                     ca_bundle: str | None) -> tuple[list[Finding], list[dict], list[dict]]:
    findings, assessments, certificates = [], [], []
    for endpoint in endpoints:
        result = assess_endpoint(endpoint, ca_bundle)
        system = cfg.system_for_endpoint(endpoint)
        sid = system.id if system else None
        der = result.pop("certificate_der")
        assessments.append(result)
        for protocol in result["legacy_protocols"]:
            findings.append(_synthetic(policy, "TLS-PROBE-PROTO-001", endpoint, protocol,
                                       f"server negotiates {protocol}", sid))
        if result["reachable"] and not result["protocol"]:
            findings.append(_synthetic(policy, "TLS-PROBE-MODERN-001", endpoint, "n/a",
                                       f"no TLS 1.2/1.3 handshake: {result['modern_error']}", sid))
        if result["verified"] is False:
            findings.append(_synthetic(policy, "TLS-PROBE-CERT-001", endpoint, "n/a",
                                       f"certificate verification failed: {result['verify_error']}", sid))
        if result["forward_secrecy"] is False:
            findings.append(_synthetic(policy, "TLS-PROBE-FS-001", endpoint, "n/a",
                                       f"{result['cipher']} over {result['protocol']} lacks (EC)DHE", sid))
        if der:
            found, info = analyze_certificate(x509.load_der_x509_certificate(der), policy, endpoint, "endpoint",
                                              cfg.cert_warn_days)
            for f in found:
                f.system = sid
            findings += found
            certificates.append(info)
    return findings, assessments, certificates


def summarize(findings: list[Finding]) -> dict[str, Any]:
    active = [f for f in findings if f.active]
    return {
        "total": len(findings), "active": len(active),
        "suppressed": sum(1 for f in findings if f.suppressed), "excepted": sum(1 for f in findings if f.exception),
        "by_algorithm": dict(Counter(f.algorithm for f in active)),
        "by_severity": dict(Counter(f.severity for f in active)),
        "by_category": dict(Counter(f.category for f in active)),
        "by_system": dict(Counter(f.system or "unassigned" for f in active)),
        "by_layer": dict(Counter(f.layer or "-" for f in active)),
        "fixable": sum(1 for f in active if f.fixable),
    }


def run_discovery(cfg: Config, policy: Policy, paths: list[Path] | None = None, probe_tls: bool = True,
                  profile_data: bool = True, extra_endpoints: list[str] | None = None,
                  binaries: list[Path] | None = None, ca_bundle: str | None = None) -> dict[str, Any]:
    scan_roots = [Path(p) for p in (paths or cfg.scan_paths)]
    exclude_dirs = set(cfg.scan_exclude) | {cfg.artifacts_dir.name, cfg.state_dir.name}
    exclude_files = [p for p in (cfg.path, cfg.keystore_path) if p]
    scanner = Scanner(policy, cfg.root, exclude_dirs, load_ignore_patterns(cfg.root, *scan_roots),
                      cfg.max_file_size, exclude_files)
    findings = scanner.scan(scan_roots)
    certificates: list[dict] = []
    if policy.has_rule("CERT-SIG-001"):
        cert_findings, certificates = scan_certificate_files(cfg, policy, scanner, scan_roots)
        findings += cert_findings
    binary_reports: list[dict] = []
    binary_paths = [Path(p) for p in [*(binaries or []), *cfg.binaries]]
    if binary_paths and policy.has_rule("MEM-BIN-NX-001"):
        binary_findings, binary_reports = scan_binaries(binary_paths, policy, scanner)
        findings += binary_findings
    for finding in findings:
        system = cfg.system_for_path(finding.location)
        finding.system = system.id if system else None

    endpoints = list(dict.fromkeys([*cfg.tls_endpoints, *[e for s in cfg.systems for e in s.endpoints],
                                    *(extra_endpoints or [])]))
    probes: list[dict] = []
    assessments: list[dict] = []
    if probe_tls and endpoints:
        if policy.has_rule("CM-PROBE-TLS-001"):
            probe_findings, probes = _des_probe_findings(cfg, policy, endpoints)
            findings += probe_findings
        if policy.has_rule("TLS-PROBE-PROTO-001"):
            bundle = ca_bundle or (str(cfg.tls_ca_bundle) if cfg.tls_ca_bundle else None)
            tls_findings, assessments, endpoint_certs = _tls_assessments(cfg, policy, endpoints, bundle)
            findings += tls_findings
            certificates += endpoint_certs

    data_profiles: list[dict] = []
    if profile_data and cfg.data_sources and policy.has_rule("CM-DATA-001"):
        data_findings, data_profiles = profile_sources(cfg, policy)
        findings += data_findings

    findings += _manual_findings(cfg, policy) if cfg.manual_assets else []
    expired = apply_exceptions(findings, cfg.exceptions())
    findings.sort(key=lambda f: (f.category, f.location, f.line or 0, f.rule_id))
    return {
        "schema": INVENTORY_SCHEMA,
        "generated": isotime(),
        "tool": {"name": "cryptomigrate", "version": __version__},
        "policy": {"id": policy.id, "name": policy.name, "version": policy.version, "source": policy.source},
        "layers": policy.packs[1:],
        "project": {k: cfg.project.get(k) for k in ("name", "organization")},
        "scan": {"roots": [str(p) for p in scan_roots], **scanner.stats, "endpoints": endpoints,
                 "data_sources": [d.name for d in cfg.data_sources] if profile_data else [],
                 "binaries": [str(p) for p in binary_paths]},
        "summary": summarize(findings),
        "probes": probes,
        "tls_assessments": assessments,
        "certificates": certificates,
        "binaries": binary_reports,
        "data_profiles": data_profiles,
        "expired_exceptions": expired,
        "findings": [f.to_dict() for f in findings],
    }


def load_findings(inventory: dict[str, Any]) -> list[Finding]:
    return [Finding.from_dict(f) for f in inventory.get("findings", [])]
