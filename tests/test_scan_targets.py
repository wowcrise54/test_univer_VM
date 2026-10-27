from __future__ import annotations

import pytest

from app.domain.scan_targets import normalize_scan_target, normalize_scan_targets


@pytest.mark.parametrize(("value", "expected"), [
    (" 10.0.0.15 ", "10.0.0.15"),
    ("10.0.1.7/24", "10.0.1.0/24"),
    ("10.0.2.1 - 10.0.2.50", "10.0.2.1-10.0.2.50"),
    ("2001:DB8::1", "2001:db8::1"),
    ("2001:db8::/32", "2001:db8::/32"),
    ("SRV01.Corp.Local.", "srv01.corp.local"),
    ("dc-01", "dc-01"),
    ("host_with_underscore.corp.local", "host_with_underscore.corp.local"),
])
def test_valid_targets_are_normalized(value, expected):
    assert normalize_scan_target(value) == expected


@pytest.mark.parametrize(("value", "message"), [
    ("", "Пустая"),
    ("10.0.0.256", "IP-адрес"),
    ("10.0.0.0/33", "IP-адрес"),
    ("10.0.0.9-10.0.0.1", "IP-адрес"),
    ("10.0.0.1-2001:db8::1", "IP-адрес"),
    ("10.0.0.1-srv.corp", "IP-адрес"),
    ("10.0.0.300-10.0.0.301", "FQDN"),
    ("-bad.corp.local", "FQDN"),
    ("srv..corp", "FQDN"),
    ("srv01.corp.local/path", "IP-адрес"),
    ("srv 01", "FQDN"),
    ("a" * 64 + ".corp", "FQDN"),
    ("a." * 130, "длиннее"),
])
def test_invalid_targets_are_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        normalize_scan_target(value)


def test_duplicates_collapse_after_normalization():
    assert normalize_scan_targets(["SRV.corp", "10.0.0.1", "srv.corp.", "10.0.0.1"]) == ["srv.corp", "10.0.0.1"]
