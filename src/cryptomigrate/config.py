"""Project configuration (``migration.yaml``): the Phase 1 charter plus every technical setting.

Relative paths resolve against the directory containing the config file. Secrets never
belong in the file: use ``${ENV_VAR}`` references in ``connect`` blocks (resolved only when
a data source is opened) and environment variables for the KEK.
"""

from __future__ import annotations

import copy
import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .crypto.envelope import ALG_IDS
from .crypto.legacy import LegacyProfile
from .util import CRITICALITIES, CRITICALITY_WEIGHT

DEFAULT_CONFIG_NAME = "migration.yaml"
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

DEFAULTS: dict[str, Any] = {
    "project": {},
    "policy": "des-to-aes",
    "layers": [],
    "layer_fail_on": "high",
    "scan": {
        "paths": ["."],
        "exclude": [".git", ".hg", ".svn", ".cryptomigrate", "node_modules", ".venv", "venv", "__pycache__", ".tox",
                    ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode", "dist", "build",
                    "target"],
        "max_file_size_kb": 2048,
        "tls_endpoints": [],
        "data_sample_size": 200,
        "binaries": [],
        "tls_ca_bundle": None,
        "cert_expiry_warn_days": 30,
    },
    "target": {"algorithm": "AES-256-GCM"},
    "keystore": {"path": ".cryptomigrate/keystore.json", "kek_env": "CRYPTOMIGRATE_KEK",
                 "kek_passphrase_env": "CRYPTOMIGRATE_KEK_PASSPHRASE", "wrap": "aes-kwp", "rsa_public_key": None,
                 "rsa_private_key_env": "CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE",
                 "rsa_passphrase_env": "CRYPTOMIGRATE_KEK_RSA_PASSPHRASE"},
    "legacy_profiles": {},
    "systems": [],
    "data_sources": [],
    "manual_assets": [],
    "migration": {"mode": "dual", "backup": True, "batch_size": 500, "throttle_ms": 0, "max_error_rate": 0.0,
                  "malware_scan": {"enabled": False, "clamd": "unix:/var/run/clamav/clamd.ctl", "timeout_s": 30}},
    "nfr": {"max_latency_increase_pct": 10, "benchmark_record_bytes": 256, "benchmark_iterations": 2000},
    "governance": {"require_change_ticket": False, "max_artifact_age_days": 30, "signoffs": {}, "exceptions": [],
                   "dual_control": False, "require_signed_commits": False, "approvals": {}},
    "artifacts_dir": "artifacts",
    "state_dir": ".cryptomigrate",
}


class ConfigError(ValueError):
    pass


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def glob_match(path: str, pattern: str) -> bool:
    """fnmatch-style glob where ``*`` also crosses directories; ``dir/`` and ``dir/**`` match a subtree."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if pattern.endswith("/**"):
        pattern = pattern[:-3] + "/*"
    elif pattern.endswith("/"):
        pattern += "*"
    if fnmatch.fnmatchcase(path, pattern):
        return True
    # gitignore-like: a pattern without "/" also matches the file name at any depth
    return "/" not in pattern and fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pattern)


def resolve_env_refs(value: Any) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ConfigError(f"environment variable {name} referenced in config is not set")
            return os.environ[name]
        return ENV_REF.sub(repl, value)
    if isinstance(value, dict):
        return {k: resolve_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env_refs(v) for v in value]
    return value


@dataclass
class System:
    id: str
    name: str
    owner: str | None = None
    criticality: str = "medium"
    data_classification: str | None = None
    wave: int | None = None
    paths: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)


@dataclass
class ColumnSpec:
    name: str
    legacy_profile: str
    storage: str = "text"  # text (VARCHAR/TEXT) | blob (BLOB/BYTEA/VARBINARY)
    max_length: int | None = None


@dataclass
class DataSource:
    name: str
    adapter: str  # sql | files
    system: str | None = None
    wave: int | None = None
    aad: str = ""
    batch_size: int = 500
    throttle_ms: int = 0
    max_error_rate: float = 0.0
    # sql
    driver: str | None = None
    connect: dict[str, Any] = field(default_factory=dict)
    table: str | None = None
    primary_key: str | None = None
    columns: list[ColumnSpec] = field(default_factory=list)
    limit_style: str = "limit"  # limit | fetch | top
    # files
    path: Path | None = None
    glob: str = "**/*"
    legacy_profile: str | None = None

    def profiles(self) -> set[str]:
        names = {c.legacy_profile for c in self.columns}
        if self.legacy_profile:
            names.add(self.legacy_profile)
        return names

    def render_aad(self, column: str = "", pk: Any = "", relpath: str = "") -> str:
        return self.aad.format(source=self.name, table=self.table or "", column=column, pk=pk, relpath=relpath)


@dataclass
class Config:
    path: Path | None
    root: Path
    raw: dict[str, Any]
    project: dict[str, Any]
    policy: str
    scan_paths: list[Path]
    scan_exclude: list[str]
    max_file_size: int
    tls_endpoints: list[str]
    data_sample_size: int
    target_algorithm: str
    keystore_path: Path
    kek_env: str
    kek_passphrase_env: str
    legacy_profiles: dict[str, LegacyProfile]
    systems: list[System]
    data_sources: list[DataSource]
    manual_assets: list[dict[str, Any]]
    migration: dict[str, Any]
    nfr: dict[str, Any]
    governance: dict[str, Any]
    artifacts_dir: Path
    state_dir: Path
    layers: list[str] = field(default_factory=list)
    layer_fail_on: str = "high"
    binaries: list[Path] = field(default_factory=list)
    tls_ca_bundle: Path | None = None
    cert_warn_days: int = 30
    keystore_wrap: dict[str, Any] = field(default_factory=dict)
    malware: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ derived
    @property
    def migration_mode(self) -> str:
        return self.migration.get("mode", "dual")

    @property
    def audit_path(self) -> Path:
        return self.state_dir / "audit.log"

    def artifact(self, *parts: str) -> Path:
        return self.artifacts_dir.joinpath(*parts)

    def state(self, *parts: str) -> Path:
        return self.state_dir.joinpath(*parts)

    def system(self, system_id: str | None) -> System | None:
        return next((s for s in self.systems if s.id == system_id), None)

    def system_for_path(self, relpath: str) -> System | None:
        for system in self.systems:
            if any(glob_match(relpath, p) for p in system.paths):
                return system
        return None

    def system_for_endpoint(self, endpoint: str) -> System | None:
        return next((s for s in self.systems if endpoint in s.endpoints), None)

    def source(self, name: str) -> DataSource:
        for ds in self.data_sources:
            if ds.name == name:
                return ds
        raise ConfigError(f"unknown data source {name!r}; configured: {[d.name for d in self.data_sources]}")

    def wave_of(self, system_id: str | None) -> int:
        """Explicit wave, else derived from criticality: low-criticality systems go first (risk-based rollout)."""
        system = self.system(system_id)
        if system and system.wave is not None:
            return system.wave
        if system is None:
            return max([s.wave or 0 for s in self.systems] + [len(CRITICALITIES)]) + 1
        return CRITICALITY_WEIGHT.get(system.criticality, 2)

    def source_wave(self, ds: DataSource) -> int:
        return ds.wave if ds.wave is not None else self.wave_of(ds.system)

    def exceptions(self) -> list[dict[str, Any]]:
        return list(self.governance.get("exceptions") or [])

    def signoff(self, gate: str) -> dict[str, Any] | None:
        value = (self.governance.get("signoffs") or {}).get(gate)
        return value if isinstance(value, dict) and value.get("by") else None


def _as_path(root: Path, value: str | Path) -> Path:
    p = Path(os.path.expanduser(str(value)))
    return p if p.is_absolute() else (root / p)


def _parse_profiles(raw: dict[str, Any]) -> dict[str, LegacyProfile]:
    profiles = {}
    for name, spec in (raw or {}).items():
        spec = spec or {}
        try:
            profiles[name] = LegacyProfile(
                name=name,
                algorithm=str(spec.get("algorithm", "3DES")).upper(),
                mode=str(spec.get("mode", "CBC")).upper(),
                key_id=str(spec.get("key_id", f"legacy-{name}")),
                iv=str(spec.get("iv", "prefix" if str(spec.get("mode", "CBC")).upper() == "CBC" else "none")),
                padding=str(spec.get("padding", "pkcs7")).lower(),
                encoding=str(spec.get("encoding", "base64")).lower(),
                key_transport=str(spec.get("key_transport", "none")).lower(),
                rsa_key_bits=int(spec.get("rsa_key_bits", 2048)),
            ).validate()
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    return profiles


def _parse_systems(raw: list[dict[str, Any]]) -> list[System]:
    systems, seen = [], set()
    for item in raw or []:
        if "id" not in item:
            raise ConfigError(f"system entry missing 'id': {item}")
        if item["id"] in seen:
            raise ConfigError(f"duplicate system id {item['id']!r}")
        seen.add(item["id"])
        criticality = str(item.get("criticality", "medium")).lower()
        if criticality not in CRITICALITIES:
            raise ConfigError(f"system {item['id']}: criticality must be one of {CRITICALITIES}")
        systems.append(System(id=str(item["id"]), name=str(item.get("name", item["id"])), owner=item.get("owner"),
                              criticality=criticality, data_classification=item.get("data_classification"),
                              wave=item.get("wave"), paths=list(item.get("paths") or []),
                              endpoints=[str(e) for e in item.get("endpoints") or []]))
    return systems


def _parse_sources(raw: list[dict[str, Any]], root: Path, migration: dict[str, Any],
                   profiles: dict[str, LegacyProfile], systems: list[System]) -> list[DataSource]:
    sources, seen = [], set()
    system_ids = {s.id for s in systems}
    for item in raw or []:
        name = item.get("name")
        if not name or name in seen:
            raise ConfigError(f"data source needs a unique 'name': {item}")
        seen.add(name)
        adapter = item.get("adapter", "sql")
        if item.get("system") and item["system"] not in system_ids:
            raise ConfigError(f"data source {name}: system {item['system']!r} is not defined under systems")
        common = dict(name=name, adapter=adapter, system=item.get("system"), wave=item.get("wave"),
                      batch_size=int(item.get("batch_size", migration.get("batch_size", 500))),
                      throttle_ms=int(item.get("throttle_ms", migration.get("throttle_ms", 0))),
                      max_error_rate=float(item.get("max_error_rate", migration.get("max_error_rate", 0.0))))
        if adapter == "sql":
            for key in ("driver", "table", "primary_key", "columns"):
                if not item.get(key):
                    raise ConfigError(f"data source {name}: sql adapter requires '{key}'")
            for ident in (item["table"], item["primary_key"], *[c["name"] for c in item["columns"]]):
                if not IDENT_RE.match(str(ident)):
                    raise ConfigError(f"data source {name}: invalid SQL identifier {ident!r}")
            columns = [ColumnSpec(name=c["name"], legacy_profile=c.get("legacy_profile", item.get("legacy_profile")),
                                  storage=c.get("storage", "text"), max_length=c.get("max_length"))
                       for c in item["columns"]]
            connect = dict(item.get("connect") or {})
            if item["driver"] == "sqlite3" and "database" in connect and connect["database"] != ":memory:" \
                    and "${" not in str(connect["database"]):
                connect["database"] = str(_as_path(root, connect["database"]))
            ds = DataSource(**common, aad=item.get("aad", "{table}.{column}#{pk}"), driver=item["driver"],
                            connect=connect, table=item["table"], primary_key=item["primary_key"], columns=columns,
                            limit_style=item.get("limit_style", "limit"))
        elif adapter == "files":
            if not item.get("path") or not item.get("legacy_profile"):
                raise ConfigError(f"data source {name}: files adapter requires 'path' and 'legacy_profile'")
            ds = DataSource(**common, aad=item.get("aad", ""), path=_as_path(root, item["path"]),
                            glob=item.get("glob", "**/*"), legacy_profile=item["legacy_profile"])
        else:
            raise ConfigError(f"data source {name}: unknown adapter {adapter!r} (use sql or files)")
        for profile in ds.profiles():
            if profile not in profiles:
                raise ConfigError(f"data source {name}: legacy profile {profile!r} is not defined")
        for column in ds.columns:
            if column.storage not in ("text", "blob"):
                raise ConfigError(f"data source {name}: column storage must be text or blob")
            if column.storage == "text" and profiles[column.legacy_profile].encoding == "raw":
                raise ConfigError(f"data source {name}: text column {column.name} cannot use a raw-encoded profile")
        try:
            ds.render_aad(column="c", pk=1, relpath="r")
        except (KeyError, IndexError) as exc:
            raise ConfigError(f"data source {name}: aad template uses unknown field {exc}") from exc
        sources.append(ds)
    return sources


def build_config(raw: dict[str, Any], root: Path, path: Path | None = None) -> Config:
    data = _merge(DEFAULTS, raw or {})
    target = str(data["target"]["algorithm"]).upper()
    if target not in ALG_IDS:
        raise ConfigError(f"target.algorithm must be one of {sorted(ALG_IDS)} (authenticated AES-GCM)")
    migration = data["migration"]
    if migration.get("mode", "dual") not in ("dual", "strict"):
        raise ConfigError("migration.mode must be 'dual' or 'strict'")
    from .util import SEVERITIES

    if not isinstance(data["layers"], list) or not all(isinstance(x, str) for x in data["layers"]):
        raise ConfigError("layers must be a list of policy pack ids or paths")
    if str(data["layer_fail_on"]).lower() not in SEVERITIES:
        raise ConfigError(f"layer_fail_on must be one of {SEVERITIES}")
    if data["keystore"].get("wrap", "aes-kwp") not in ("aes-kwp", "rsa-aes-kwp"):
        raise ConfigError("keystore.wrap must be aes-kwp or rsa-aes-kwp")
    wrap_options = {k: data["keystore"].get(k) for k in ("wrap", "rsa_public_key", "rsa_private_key_env",
                                                         "rsa_passphrase_env")}
    if wrap_options["rsa_public_key"]:
        wrap_options["rsa_public_key"] = str(_as_path(root, wrap_options["rsa_public_key"]))
    profiles = _parse_profiles(data["legacy_profiles"])
    systems = _parse_systems(data["systems"])
    state_dir = _as_path(root, data["state_dir"])
    return Config(
        path=path, root=root, raw=data, project=data["project"] or {}, policy=str(data["policy"]),
        scan_paths=[_as_path(root, p) for p in data["scan"]["paths"]],
        scan_exclude=list(data["scan"]["exclude"]),
        max_file_size=int(data["scan"]["max_file_size_kb"]) * 1024,
        tls_endpoints=[str(e) for e in data["scan"].get("tls_endpoints") or []],
        data_sample_size=int(data["scan"].get("data_sample_size", 200)),
        target_algorithm=target,
        keystore_path=_as_path(root, data["keystore"]["path"]),
        kek_env=data["keystore"]["kek_env"], kek_passphrase_env=data["keystore"]["kek_passphrase_env"],
        legacy_profiles=profiles, systems=systems,
        data_sources=_parse_sources(data["data_sources"], root, migration, profiles, systems),
        manual_assets=list(data["manual_assets"] or []), migration=migration, nfr=data["nfr"],
        governance=data["governance"], artifacts_dir=_as_path(root, data["artifacts_dir"]), state_dir=state_dir,
        layers=list(data["layers"]), layer_fail_on=str(data["layer_fail_on"]).lower(),
        binaries=[_as_path(root, p) for p in data["scan"].get("binaries") or []],
        tls_ca_bundle=_as_path(root, data["scan"]["tls_ca_bundle"]) if data["scan"].get("tls_ca_bundle") else None,
        cert_warn_days=int(data["scan"].get("cert_expiry_warn_days", 30)), keystore_wrap=wrap_options,
        malware=dict(migration.get("malware_scan") or {}),
    )


def load_config(path: str | Path | None = None, require: bool = False) -> Config:
    if path is None:
        candidate = Path.cwd() / DEFAULT_CONFIG_NAME
        if not candidate.exists():
            if require:
                raise ConfigError(f"no {DEFAULT_CONFIG_NAME} found - run `cryptomigrate init` or pass --config")
            return build_config({}, Path.cwd())
        path = candidate
    path = Path(path).resolve()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return build_config(raw, path.parent, path)
