"""Cipher-list parsing shared by discovery validators and remediation fixers.

Validators run after a rule's regex matches and decide whether the match is a real
finding (``None`` = not a finding; a dict may refine algorithm/severity/detail).
Fixers take one line plus the rule's match on that line and return the corrected line,
or ``None`` when the change cannot be made safely and needs a human.
"""

from __future__ import annotations

import re
from typing import Any

# ------------------------------------------------------------------ OpenSSL syntax
_NARROWING = ("AES", "CHACHA", "CAMELLIA", "ARIA", "SEED", "NULL", "RC4", "IDEA", "GOST", "SM4")


def _openssl_parts(value: str) -> tuple[str, str, str, str]:
    """Split a directive value into (quote, protocol prefix, cipher list, trailing whitespace)."""
    stripped = value.rstrip()
    trailing = value[len(stripped):]
    quote, inner = "", stripped.strip()
    if len(inner) >= 2 and inner[0] in "'\"" and inner[-1] == inner[0]:
        quote, inner = inner[0], inner[1:-1]
    proto = ""
    parts = inner.split()
    if len(parts) == 2 and parts[0].upper() in ("SSL", "TLSV1.3"):  # Apache 2.4: SSLCipherSuite [protocol] spec
        proto, inner = parts[0] + " ", parts[1]
    return quote, proto, inner, trailing


def _tokens(cipher_list: str) -> list[str]:
    return [t for t in re.split(r"[:,\s]+", cipher_list) if t]


def _is_positive_des(token: str) -> bool:
    return token[:1] not in ("!", "-", "@") and "DES" in token.upper()


def _token_alg(token: str) -> str:
    upper = token.upper()
    return "3DES" if ("3DES" in upper or "CBC3" in upper or "DES-EDE" in upper) else "DES"


def analyze_openssl(value: str) -> dict[str, Any]:
    _, _, inner, _ = _openssl_parts(value)
    tokens = _tokens(inner)
    upper = [t.upper() for t in tokens]
    excluded = any(t in ("!3DES", "-3DES", "!DES", "-DES") for t in upper)
    explicit = [t for t in tokens if _is_positive_des(t)]
    broad = [t for t in tokens if t[:1] not in "!-@" and "-" not in t.lstrip("+")
             and not any(n in t.upper() for n in _NARROWING)]
    return {"tokens": tokens, "explicit": explicit, "excluded": excluded, "implicit": bool(broad) and not excluded,
            "broad": broad}


def validate_openssl(match: re.Match, text: str) -> dict[str, Any] | None:
    analysis = analyze_openssl(match.group("value"))
    if analysis["explicit"]:
        algorithms = {_token_alg(t) for t in analysis["explicit"]}
        return {"algorithm": "DES" if "DES" in algorithms else "3DES",
                "detail": "enables " + ", ".join(analysis["explicit"])}
    if analysis["implicit"]:
        return {"algorithm": "3DES", "severity": "low", "confidence": "low",
                "detail": f"broad alias {', '.join(analysis['broad'])} without !3DES - includes 3DES on older OpenSSL "
                          "builds (HIGH did before 1.1.0); add !3DES:!DES as defence in depth"}
    return None


def fix_openssl(line: str, match: re.Match) -> str | None:
    start, end = match.span("value")
    quote, proto, inner, trailing = _openssl_parts(line[start:end])
    kept = [t for t in _tokens(inner) if not _is_positive_des(t)]
    if not any(t[:1] not in "!-@" for t in kept):
        return None  # nothing but DES suites: a human must choose replacements
    upper = {t.upper() for t in kept}
    kept += [neg for neg in ("!3DES", "!DES") if neg not in upper]
    return line[:start] + f"{quote}{proto}{':'.join(kept)}{quote}{trailing}" + line[end:]


# ----------------------------------------------------------------------- OpenSSH
_SSH_DES = re.compile(r"^(?:3des|des)(?:-[a-z0-9]+)*(?:@[a-z0-9.\-]+)?$", re.I)


def _ssh_split(value: str) -> tuple[str, list[str], str]:
    stripped = value.rstrip()
    trailing = value[len(stripped):]
    prefix = stripped[:1] if stripped[:1] in "+-^" else ""
    body = stripped[1:] if prefix else stripped
    return prefix, [t.strip() for t in body.split(",") if t.strip()], trailing


def validate_ssh(match: re.Match, text: str) -> dict[str, Any] | None:
    prefix, tokens, _ = _ssh_split(match.group("value"))
    if prefix == "-":
        return None  # a removal list naming 3des-cbc is the fix, not the problem
    bad = [t for t in tokens if _SSH_DES.match(t)]
    if not bad:
        return None
    return {"algorithm": "3DES" if all(t.lower().startswith("3des") for t in bad) else "DES",
            "mode": "CBC" if any("cbc" in t.lower() for t in bad) else None, "detail": "enables " + ", ".join(bad)}


def fix_ssh(line: str, match: re.Match) -> str | None:
    start, end = match.span("value")
    prefix, tokens, trailing = _ssh_split(line[start:end])
    if prefix == "-":
        return None
    kept = [t for t in tokens if not _SSH_DES.match(t)]
    if not kept:
        indent = line[: len(line) - len(line.lstrip())]
        return (f"{indent}# {line.strip()}  # disabled by cryptomigrate: only DES-family ciphers were listed "
                "(OpenSSH defaults exclude 3DES)")
    return line[:start] + prefix + ",".join(kept) + trailing + line[end:]


# ------------------------------------------------------------------- IANA suites
IANA_DES = re.compile(r"\b(?:TLS|SSL)_[A-Za-z0-9_]*?WITH_(?:3DES_EDE_CBC|DES_CBC|DES40_CBC|DES_CBC_40)_[A-Z0-9_]+\b")
_EXCLUDE_CONTEXT = re.compile(r"(?i)exclud|disabl|blacklist|denylist|\bdeny\b|reject|blocked|forbid")
_RUN = re.compile(r"[A-Za-z0-9_]+(?:[ \t]*,[ \t]*[A-Za-z0-9_]+)*")


def validate_iana(match: re.Match, text: str) -> dict[str, Any] | None:
    line_start = match.string.rfind("\n", 0, match.start()) + 1
    window_start = line_start
    for _ in range(2):  # current line plus the two before it
        window_start = match.string.rfind("\n", 0, max(0, window_start - 1)) + 1
    if _EXCLUDE_CONTEXT.search(match.string[window_start:match.start()]):
        return None  # e.g. Jetty ExcludeCipherSuites / jdk.tls.disabledAlgorithms
    return {}


def fix_iana(line: str, match: re.Match) -> str | None:
    out, pos, changed = [], 0, False
    for run in _RUN.finditer(line):
        text = run.group(0)
        if not IANA_DES.search(text):
            continue
        separator = re.search(r"[ \t]*,[ \t]*", text)
        items = re.split(r"[ \t]*,[ \t]*", text)
        kept = [i for i in items if not IANA_DES.fullmatch(i)]
        if not kept:
            return None  # the list would be empty (or a lone XML <Item>): manual change
        out += [line[pos:run.start()], (separator.group(0) if separator else ",").join(kept)]
        pos, changed = run.end(), True
    if not changed:
        return None
    out.append(line[pos:])
    return "".join(out)


# ------------------------------------------------------------- TLS protocol versions
_PROTO = re.compile(r"(?P<prefix>>=\s*|[!+\-])?(?P<name>SSLv2|SSLv3|TLSv1(?:[._][0-3])?|all)(?![\w.])", re.I)
_CANON = {"sslv2": "SSLv2", "sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1.0": "TLSv1.0", "tlsv1_0": "TLSv1.0",
          "tlsv1.1": "TLSv1.1", "tlsv1_1": "TLSv1.1", "tlsv1.2": "TLSv1.2", "tlsv1_2": "TLSv1.2",
          "tlsv1.3": "TLSv1.3", "tlsv1_3": "TLSv1.3", "all": "all"}
_ORDER = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
LEGACY_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
_MIN_DIRECTIVES = {"minprotocol", "ssl-min-ver", "ssl_min_protocol"}
_APACHE = {"sslprotocol", "sslproxyprotocol"}
_SPELLING = {"SSLv3": "SSLv3", "TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1.1"}


def _canon(token: str) -> str:
    return _CANON.get(token.lstrip("+").lower(), token)


def _proto_parts(match: re.Match) -> tuple[str, str, tuple[int, int]]:
    groups = match.groupdict()
    directive = next((v for k, v in groups.items() if k.startswith("directive") and v), "")
    for key, value in groups.items():
        if key.startswith("value") and value is not None:
            return directive.lower(), value, match.span(key)
    return directive.lower(), "", (match.end(), match.end())


def enabled_legacy_protocols(directive: str, value: str) -> list[str]:
    tokens = [((m.group("prefix") or "").replace(" ", ""), _canon(m.group("name"))) for m in _PROTO.finditer(value)]
    if not tokens:
        return []
    if directive in _MIN_DIRECTIVES or any(p == ">=" for p, _ in tokens):
        floor = next((n for p, n in tokens if p == ">=" or directive in _MIN_DIRECTIVES), "TLSv1.2")
        return [p for p in _ORDER[_ORDER.index(floor):] if p in LEGACY_PROTOCOLS] if floor in _ORDER else []
    negated = {n for p, n in tokens if p in ("!", "-")}
    positive = [n for p, n in tokens if p in ("", "+")]
    if "all" in positive or not positive:  # Apache 'all', or Postfix/Dovecot exclusion-only lists
        return [p for p in ("SSLv3", "TLSv1.0", "TLSv1.1") if p not in negated]
    return [p for p in dict.fromkeys(positive) if p in LEGACY_PROTOCOLS and p not in negated]


def validate_tls_protocols(match: re.Match, text: str) -> dict[str, Any] | None:
    directive, value, _ = _proto_parts(match)
    legacy = enabled_legacy_protocols(directive, value)
    if not legacy:
        return None
    worst = min(legacy, key=_ORDER.index)
    return {"algorithm": worst, "severity": "critical" if worst in ("SSLv2", "SSLv3") else "high",
            "detail": "enables " + ", ".join(legacy)}


def fix_tls_protocols(line: str, match: re.Match) -> str | None:
    directive, value, (start, end) = _proto_parts(match)
    legacy = enabled_legacy_protocols(directive, value)
    if not legacy:
        return None
    body = value.rstrip()
    trailing = value[len(body):]
    tokens = list(_PROTO.finditer(body))
    floor = next((m for m in tokens if directive in _MIN_DIRECTIVES or (m.group("prefix") or "").startswith(">=")),
                 None)
    if floor is not None:  # minimum-version settings: raise the floor to TLS 1.2
        new = body[:floor.start("name")] + "TLSv1.2" + body[floor.end("name"):]
    elif not [m for m in tokens if (m.group("prefix") or "") in ("", "+")] or any(
            _canon(m.group("name")) == "all" for m in tokens if (m.group("prefix") or "") in ("", "+")):
        mark = "-" if directive in _APACHE else "!"  # 'all' / exclusion lists: exclude in the list's own syntax
        sep = ", " if "," in body else " "
        new = body + "".join(f"{sep}{mark}{_SPELLING[p]}" for p in legacy if p in _SPELLING)
    else:  # explicit lists: drop the legacy versions, keep everything else
        if ", " in body:
            sep = ", "
        elif "," in body:
            sep = ","
        elif "+" in body.lstrip("+") and re.fullmatch(r"[\w.+]+", body):
            sep = "+"
        else:
            sep = " "
        items = [i for i in re.split(r"\s*,\s*|\s+|(?<=\w)\+(?=\w)", body) if i]
        kept = [i for i in items if _canon(i) not in LEGACY_PROTOCOLS]
        if not any(_canon(i) in ("TLSv1.2", "TLSv1.3") for i in kept):
            return None  # nothing modern left: a human must decide
        new = sep.join(kept)
    return line[:start] + new + trailing + line[end:]


# ------------------------------------------------------------- 802.1X / enterprise Wi-Fi
_CA_SETTINGS = re.compile(r"(?im)^\s*(?:ca_cert2?|ca-cert|ca_path|ca-path|domain_suffix_match|domain-suffix-match|"
                          r"domain_match|domain-match|altsubject_match)\s*=")


def validate_eap_ca(match: re.Match, text: str) -> dict[str, Any] | None:
    block = match.group(0)
    if not re.search(r"(?i)mschapv2", block) or _CA_SETTINGS.search(block):
        return None
    return {"detail": "PEAP/TTLS with MS-CHAPv2 and no RADIUS server-certificate validation (ca_cert / domain match)"}


# ------------------------------------------------------------- private keys in files
def validate_pem_key(match: re.Match, text: str) -> dict[str, Any] | None:
    following = match.string[match.end():match.end() + 200]
    if "ENCRYPTED" in match.group(0) or "Proc-Type: 4,ENCRYPTED" in following:
        return {"severity": "medium", "detail": "encrypted private key stored in the repository"}
    return {"detail": "unencrypted private key stored in the repository"}


VALIDATORS = {"openssl-cipher-list": validate_openssl, "ssh-cipher-list": validate_ssh, "iana-suite": validate_iana,
              "tls-protocols": validate_tls_protocols, "eap-ca": validate_eap_ca, "pem-private-key": validate_pem_key}
FIXERS = {"openssl-cipher-list": fix_openssl, "ssh-cipher-list": fix_ssh, "iana-cipher-list": fix_iana,
          "tls-protocols": fix_tls_protocols}
