# Copyright (C) 2003-2026  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of Paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Offline auditing of SSH server algorithm policies.

This module never opens a connection: it takes an inventory of an SSH
server's declared algorithm lists (for example, the output of
``ssh -Q`` combined with the server's effective configuration, or a
hand-maintained asset registry) and classifies each entry.

The primary entry point is :func:`audit_servers`, which returns a report
containing per-host findings (weak algorithms, missing modern
algorithms, certificate validity, incomplete inventories) plus aggregate
statistics suitable for an asset-management report.

Distinct from :class:`paramiko.transport.Transport`, whose algorithm
tables describe what *Paramiko itself* supports and negotiates.  The
policy here is deliberately independent, so that a server's declared
lists can be judged without altering negotiation behavior.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

__all__ = ["audit_servers", "AuditResult", "SkillPolicy", "Weakness"]

# Issue codes, in report order.
MISSING_FIELD = "missing_field"
WEAK_KEX = "weak_kex"
WEAK_HOST_KEY = "weak_host_key"
WEAK_CIPHER = "weak_cipher"
WEAK_MAC = "weak_mac"
MODERN_MISSING = "modern_missing"
CERT_EXPIRED = "cert_expired"
CERT_NOT_YET_VALID = "cert_not_yet_valid"

_ISSUE_ORDER = (
    MISSING_FIELD,
    WEAK_KEX,
    WEAK_HOST_KEY,
    WEAK_CIPHER,
    WEAK_MAC,
    MODERN_MISSING,
    CERT_EXPIRED,
    CERT_NOT_YET_VALID,
)

# Issues that the ``allow_weak`` policy downgrades.  Algorithm-choice
# findings are policy decisions the operator may accept for legacy
# interoperability; an incomplete inventory or a certificate problem is
# never acceptable just because weak algorithms are allowed.
_DOWNGRADABLE = frozenset(
    {WEAK_KEX, WEAK_HOST_KEY, WEAK_CIPHER, WEAK_MAC, MODERN_MISSING}
)

# Inventory fields that must be present, and the weak-issue code / weak
# bucket / modern-algorithm family each maps to.
_FIELD_SPECS = ("kex", "host_keys", "ciphers", "macs")
_WEAK_BUCKETS = {
    "kex": "kex",
    "host_keys": "host_key",
    "ciphers": "cipher",
    "macs": "mac",
}
_WEAK_ISSUES = {
    "kex": WEAK_KEX,
    "host_keys": WEAK_HOST_KEY,
    "ciphers": WEAK_CIPHER,
    "macs": WEAK_MAC,
}

_EXACT_WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
    }
)


def _as_algorithm_list(value):
    """Normalize an inventory field into a list of algorithm names.

    Returns ``None`` when the value is absent or cannot be interpreted as
    an algorithm list, which callers treat the same as a missing field.
    """
    if value is None:
        return None
    if isinstance(value, str):
        candidates = value.split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        candidates = value
    else:
        try:
            candidates = list(value)
        except TypeError:
            return None
    out = []
    for entry in candidates:
        if entry is None:
            continue
        name = str(entry).strip()
        if name:
            out.append(name)
    return out


def _dedupe(names):
    seen = set()
    out = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _is_weak_kex(name):
    name = name.lower()
    return name in _EXACT_WEAK_KEX or "-sha1" in name


def _is_weak_host_key(name):
    name = name.lower()
    return (
        name == "ssh-dss"
        or name.startswith("ssh-dss-")
        or name == "ssh-rsa"
        or name.startswith("ssh-rsa-cert-")
    )


def _is_weak_cipher(name):
    name = name.lower()
    return name == "3des-cbc" or name.endswith("-cbc") or name.startswith(
        "arcfour"
    )


def _is_weak_mac(name):
    name = name.lower()
    return name.startswith("hmac-md5") or name.startswith("hmac-sha1")


def _is_modern_kex(name):
    name = name.lower()
    return (
        "curve25519" in name
        or "mlkem" in name
        or "sntrup" in name
        or "sha2" in name
        or "sha256" in name
        or "sha512" in name
    )


def _is_modern_cipher(name):
    name = name.lower()
    return "chacha20" in name or ("aes" in name and "-gcm" in name)


def _is_modern_mac(name):
    name = name.lower()
    return "-etm@openssh.com" in name or "sha2" in name


_WEAK_PREDICATES = {
    "kex": _is_weak_kex,
    "host_keys": _is_weak_host_key,
    "ciphers": _is_weak_cipher,
    "macs": _is_weak_mac,
}
_MODERN_PREDICATES = {
    "kex": _is_modern_kex,
    "ciphers": _is_modern_cipher,
    "macs": _is_modern_mac,
}
_MODERN_HINTS = {
    "kex": "no curve25519 or SHA-2 key exchange",
    "ciphers": "no chacha20 or AES-GCM cipher",
    "macs": "no ETM or SHA-2 MAC",
}


def _parse_timestamp(value):
    """Parse an ISO-8601 timestamp (or datetime) into an aware UTC one.

    Returns ``None`` for absent or unparseable values.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Feed fromisoformat something it accepts; it gained a trailing-Z
        # form only in 3.11, while Paramiko still supports 3.9.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_now(now):
    if now is None:
        return datetime.now(timezone.utc)
    resolved = _parse_timestamp(now)
    if resolved is None:
        raise ValueError("invalid 'now' timestamp: {!r}".format(now))
    return resolved


@dataclass
class SkillPolicy(object):
    """Policy knobs for :func:`audit_servers`.

    :param bool allow_weak: When true, weak-algorithm and
        missing-modern-algorithm findings are downgraded to
        ``severity="warn"`` and no longer make ``ok`` false.  Their issue
        codes stay in ``issues``.  Incomplete inventories and certificate
        problems still fail.
    """

    allow_weak: bool = False


@dataclass
class Weakness(object):
    """The weak algorithms found on one host, grouped by family."""

    kex: List[str] = field(default_factory=list)
    host_key: List[str] = field(default_factory=list)
    cipher: List[str] = field(default_factory=list)
    mac: List[str] = field(default_factory=list)

    def as_dict(self):
        return {
            "kex": list(self.kex),
            "host_key": list(self.host_key),
            "cipher": list(self.cipher),
            "mac": list(self.mac),
        }


@dataclass
class AuditResult(object):
    """Result of :func:`audit_servers`.

    :attr items: One dict per input config, in input order.
    :attr stats: Aggregate counts with keys ``ok``, ``bad``, ``by_host``
        and ``by_issue``.
    """

    items: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


def _audit_one(index, config, policy, now):
    config = config if isinstance(config, dict) else {}
    host = config.get("host")
    host = "<unknown>" if host is None else str(host)

    weak = Weakness()
    issues = set()
    details = []
    missing = []

    for key in _FIELD_SPECS:
        algorithms = _as_algorithm_list(config.get(key))
        if not algorithms:
            missing.append(key)
            continue

        predicate = _WEAK_PREDICATES[key]
        weak_names = [name for name in algorithms if predicate(name)]
        if weak_names:
            bucket = _WEAK_BUCKETS[key]
            weak_names = _dedupe(weak_names)
            setattr(weak, bucket, weak_names)
            issue = _WEAK_ISSUES[key]
            issues.add(issue)
            details.append("{}: {}".format(issue, ", ".join(weak_names)))

        modern_predicate = _MODERN_PREDICATES.get(key)
        if modern_predicate is not None and not any(
            modern_predicate(name) for name in algorithms
        ):
            issues.add(MODERN_MISSING)
            details.append(
                "modern_missing ({}): {}".format(key, _MODERN_HINTS[key])
            )

    if missing:
        issues.add(MISSING_FIELD)
        details.append("missing_field: {}".format(", ".join(missing)))

    certificate = config.get("certificate")
    if certificate is not None:
        # Absent certificate means "not applicable"; a present mapping is
        # judged only on the bounds it actually declares.
        if not isinstance(certificate, dict):
            certificate = {}
        not_before = _parse_timestamp(certificate.get("not_before"))
        not_after = _parse_timestamp(certificate.get("not_after"))
        if not_after is not None and now > not_after:
            issues.add(CERT_EXPIRED)
            details.append("cert_expired: not_after={}".format(not_after))
        if not_before is not None and now < not_before:
            issues.add(CERT_NOT_YET_VALID)
            details.append("cert_not_yet_valid: not_before={}".format(
                not_before
            ))

    ordered_issues = [code for code in _ISSUE_ORDER if code in issues]
    blocking = [
        code
        for code in ordered_issues
        if code not in _DOWNGRADABLE or not policy.allow_weak
    ]
    ok = not blocking
    if not ordered_issues:
        severity = "ok"
    elif ok:
        severity = "warn"
    else:
        severity = "error"

    return {
        "index": index,
        "host": host,
        "ok": ok,
        "issues": ordered_issues,
        "weak": weak.as_dict(),
        "severity": severity,
        "details": details,
    }


def audit_servers(configs, policy=None, now=None):
    """Audit declared SSH server algorithms without connecting.

    :param configs: Iterable of mappings.  Each mapping may contain
        ``host`` plus the inventory keys ``kex``, ``host_keys``,
        ``ciphers``, ``macs`` and ``certificate``.  ``certificate``, when
        present, is a mapping with optional ``not_before`` / ``not_after``
        ISO-8601 timestamps.  A missing inventory field yields
        ``missing_field``.
    :param policy: Optional mapping, or :class:`SkillPolicy`.  Supports
        ``{"allow_weak": True}`` to downgrade weak-algorithm findings to
        ``severity="warn"`` while keeping their issue codes.
    :param now: Reference timestamp for certificate validity, as an
        ISO-8601 string or :class:`datetime.datetime`.  Defaults to the
        current UTC time.
    :return: :class:`AuditResult` with per-host ``items`` and aggregate
        ``stats`` (``ok``, ``bad``, ``by_host``, ``by_issue``), where
        ``by_host`` and ``by_issue`` count findings.
    """
    if policy is None:
        policy = SkillPolicy()
    elif isinstance(policy, dict):
        policy = SkillPolicy(allow_weak=bool(policy.get("allow_weak", False)))
    elif not isinstance(policy, SkillPolicy):
        raise TypeError("policy must be a mapping or SkillPolicy")

    reference = _resolve_now(now)

    items = []
    by_host = {}
    by_issue = {}
    ok_count = 0

    for index, config in enumerate(configs or ()):
        item = _audit_one(index, config, policy, reference)
        items.append(item)
        if item["ok"]:
            ok_count += 1
        host = item["host"]
        by_host[host] = by_host.get(host, 0) + len(item["issues"])
        for code in item["issues"]:
            by_issue[code] = by_issue.get(code, 0) + 1

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_host": dict(sorted(by_host.items())),
        "by_issue": dict(sorted(by_issue.items())),
    }
    return AuditResult(items=items, stats=stats)
