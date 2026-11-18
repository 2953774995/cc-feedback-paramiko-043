"""
Unit tests for the offline server algorithm audit in ``paramiko.audit``.
"""

import pytest

from paramiko.audit import audit_servers


GOOD = {
    "host": "10.0.0.1",
    "kex": ["curve25519-sha256", "diffie-hellman-group16-sha512"],
    "host_keys": ["ssh-ed25519", "rsa-sha2-512"],
    "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    "macs": ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"],
    "certificate": None,
}


def test_clean_config_has_no_issues():
    item = audit_servers([GOOD]).items[0]
    assert item["ok"]
    assert item["issues"] == []
    assert item["severity"] == "ok"
    assert item["weak"] == {
        "kex": [],
        "host_key": [],
        "cipher": [],
        "mac": [],
    }


@pytest.mark.parametrize(
    "field, value, bucket, issue",
    [
        ("kex", "diffie-hellman-group14-sha1", "kex", "weak_kex"),
        ("host_keys", "ssh-rsa", "host_key", "weak_host_key"),
        ("ciphers", "aes192-cbc", "cipher", "weak_cipher"),
        ("macs", "hmac-sha1-96", "mac", "weak_mac"),
    ],
)
def test_weak_algorithms_are_classified(field, value, bucket, issue):
    config = dict(GOOD, **{field: [value, GOOD[field][0]]})
    item = audit_servers([config]).items[0]
    assert value in item["weak"][bucket]
    assert issue in item["issues"]
    assert not item["ok"]


def test_missing_field_reported_once():
    config = {"host": "a", "kex": ["curve25519-sha256"]}
    item = audit_servers([config]).items[0]
    assert item["issues"] == ["missing_field"]
    assert not item["ok"]


def test_modern_missing_details_name_the_family():
    config = dict(
        GOOD,
        kex=["diffie-hellman-group14-sha1"],
        ciphers=["aes128-cbc"],
        macs=["hmac-sha1"],
    )
    item = audit_servers([config]).items[0]
    assert "modern_missing" in item["issues"]
    detail = " ".join(item["details"])
    assert "kex" in detail and "ciphers" in detail and "macs" in detail


def test_certificate_bounds_respect_now():
    expired = dict(
        GOOD,
        certificate={
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        },
    )
    future = dict(
        GOOD,
        certificate={
            "not_before": "2027-01-01T00:00:00Z",
            "not_after": "2030-01-01T00:00:00Z",
        },
    )
    now = "2026-11-18T00:00:00Z"
    assert audit_servers([expired], now=now).items[0]["issues"] == [
        "cert_expired"
    ]
    assert audit_servers([future], now=now).items[0]["issues"] == [
        "cert_not_yet_valid"
    ]


def test_allow_weak_downgrades_but_keeps_codes():
    config = dict(GOOD, ciphers=["3des-cbc"])
    item = audit_servers([config], policy={"allow_weak": True}).items[0]
    assert item["ok"]
    assert item["severity"] == "warn"
    assert "weak_cipher" in item["issues"]
    # Missing inventory is never downgraded.
    broken = audit_servers(
        [{"host": "a"}], policy={"allow_weak": True}
    ).items[0]
    assert not broken["ok"]


def test_stats_and_empty_input():
    out = audit_servers(
        [
            GOOD,
            dict(GOOD, host="10.0.0.2", ciphers=["3des-cbc"]),
            {"host": "10.0.0.3"},
        ]
    )
    assert out.stats["ok"] == 1
    assert out.stats["bad"] == 2
    assert out.stats["by_host"]["10.0.0.2"] == 2
    assert out.stats["by_issue"]["missing_field"] == 1

    empty = audit_servers([])
    assert empty.items == []
    assert empty.stats == {
        "ok": 0,
        "bad": 0,
        "by_host": {},
        "by_issue": {},
    }
